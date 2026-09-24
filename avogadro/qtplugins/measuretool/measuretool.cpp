/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "measuretool.h"

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/contrastcolor.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/core/angletools.h>

#include <QAction>
#include <QtGui/QGuiApplication>
#include <QtGui/QIcon>
#include <QtGui/QMouseEvent>
#include <QtGui/QStyleHints>

#include <QDebug>

#include <algorithm>
#include <cmath>

using Avogadro::Core::contrastColor;
using Avogadro::Core::Elements;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

namespace Avogadro::QtPlugins {

namespace {

/// The values draw()'s overlay and the panel's rows both need, computed once
/// from the same positions so they can never disagree. Unset distances read
/// -1, unset angles 361 -- both outside any value the coordinate could take
/// -- matching the sentinels the overlay text has always used to mean "not
/// enough atoms picked yet".
struct GeometryValues
{
  Real distance12 = -1.0;
  Real distance23 = -1.0;
  Real distance34 = -1.0;
  Real angle123 = 361.0;
  Real angle234 = 361.0;
  Real dihedral1234 = 0.0;
};

GeometryValues computeGeometry(const QVector<Vector3>& positions)
{
  GeometryValues values;
  Vector3 v1, v2, v3;

  switch (positions.size()) {
    case 4:
      v3 = positions[3] - positions[2];
      values.distance34 = v3.norm();
      [[fallthrough]];
    case 3:
      v2 = positions[2] - positions[1];
      values.distance23 = v2.norm();
      [[fallthrough]];
    case 2:
      v1 = positions[1] - positions[0];
      values.distance12 = v1.norm();
      [[fallthrough]];
    default:
      break;
  }

  switch (positions.size()) {
    case 4:
      values.dihedral1234 = dihedralAngle(v1, v2, v3);
      values.angle234 = bondAngle(v2, v3);
      [[fallthrough]];
    case 3:
      values.angle123 = bondAngle(v1, v2);
      [[fallthrough]];
    default:
      break;
  }

  return values;
}

/// How many atoms must be picked before @p field means anything.
int requiredAtomCount(MeasureField field)
{
  switch (field) {
    case MeasureField::Distance12:
      return 2;
    case MeasureField::Distance23:
    case MeasureField::Angle123:
      return 3;
    case MeasureField::Distance34:
    case MeasureField::Angle234:
    case MeasureField::Dihedral1234:
    default:
      return 4;
  }
}

} // namespace

MeasureTool::MeasureTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_rwMolecule(nullptr), m_renderer(nullptr),
    m_dragged(false), m_widget(nullptr)
{
  QString shortcut = tr("Ctrl+8", "control-key 8");
  m_activateAction->setText(tr("Measure"));
  m_activateAction->setToolTip(
    tr("Measure Tool\t(%1)\n\n"
       "Left Mouse:\tSelect up to four Atoms.\n"
       "\tDistances are measured between 1-2 and 2-3\n"
       "\tAngle is measured between 1-3 using 2 as the common point\n"
       "\tDihedral is measured between 1-2-3-4\n"
       "Right Mouse:\tReset the measurements.\n\n"
       "Values can also be typed into the tool panel to move the atoms.")
      .arg(shortcut));
  setIcon();
}

MeasureTool::~MeasureTool()
{
  if (m_widget)
    m_widget->deleteLater();
}

void MeasureTool::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/measure_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/measure_light.svg"));
}

QWidget* MeasureTool::toolWidget() const
{
  // toolWidget() is const (it is called from a const context by the app),
  // but building the panel the first time it is asked for is not really a
  // const operation. const_cast is safe here because *this was never
  // actually const to begin with -- only this accessor is.
  const_cast<MeasureTool*>(this)->ensureWidget();
  return m_widget;
}

void MeasureTool::ensureWidget()
{
  if (m_widget)
    return;

  m_widget = new MeasureWidget;
  connect(m_widget, &QObject::destroyed, this, &MeasureTool::widgetDestroyed);
  connect(m_widget, &MeasureWidget::valueEdited, this, &MeasureTool::applyEdit);
  connect(m_widget, &MeasureWidget::editingFinished, this,
          &MeasureTool::endEditingRun);

  refreshWidget();
}

void MeasureTool::widgetDestroyed()
{
  m_widget = nullptr;
}

void MeasureTool::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &MeasureTool::moleculeChanged);

  m_atomIds.clear();
  m_molecule = mol;
  m_rwMolecule = nullptr;
  m_undoMerge.endRun();
  m_undoMerge.setUndoStack(mol ? &mol->undoMolecule()->undoStack() : nullptr);

  if (m_molecule) {
    connect(m_molecule, &QtGui::Molecule::changed, this,
            &MeasureTool::moleculeChanged);
  }

  refreshWidget();
}

void MeasureTool::setEditMolecule(QtGui::RWMolecule* mol)
{
  if (m_rwMolecule == mol)
    return;

  if (m_molecule)
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &MeasureTool::moleculeChanged);

  m_atomIds.clear();
  m_rwMolecule = mol;
  m_molecule = nullptr;
  // The app only ever calls setMolecule() in practice (see glwidget.cpp), so
  // edits from the panel are routed through m_molecule->undoMolecule().
  // Reaching this path leaves the panel showing values with editing
  // disabled, rather than crashing.
  m_undoMerge.endRun();
  m_undoMerge.setUndoStack(mol ? &mol->undoStack() : nullptr);

  refreshWidget();
}

void MeasureTool::moleculeChanged(unsigned int change)
{
  // Ignore notifications that couldn't affect what's on screen, such as
  // camera-only view state; the flags this cares about are exactly the ones
  // that can move an atom, change which atoms exist, or invalidate an
  // in-progress merge run.
  const unsigned int interesting =
    QtGui::Molecule::Atoms | QtGui::Molecule::Added | QtGui::Molecule::Removed;
  if ((change & interesting) == 0)
    return;

  refreshWidget();
}

QUndoCommand* MeasureTool::mousePressEvent(QMouseEvent* e)
{
  m_dragged = false;

  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  m_pressPosition = e->pos();

  // Deliberately leave the event unaccepted, even when an atom was hit, so
  // that it reaches the navigate tool: dragging from an atom rotates the view
  // around that atom. The atom is only added to the list on release, and only
  // if the press turns out to be a click rather than a drag.
  return nullptr;
}

QUndoCommand* MeasureTool::mouseMoveEvent(QMouseEvent* e)
{
  // Remember whether the mouse moved far enough for this to be a navigation
  // drag instead of a click. Never accept the event -- the navigate tool needs
  // it to move the camera.
  if (!m_dragged && (e->buttons() & Qt::LeftButton)) {
    QPoint delta = e->pos() - m_pressPosition;
    if (delta.manhattanLength() >=
        QGuiApplication::styleHints()->startDragDistance())
      m_dragged = true;
  }

  return nullptr;
}

QUndoCommand* MeasureTool::mouseReleaseEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  // The drag rotated the view, it wasn't a selection.
  if (m_dragged) {
    m_dragged = false;
    return nullptr;
  }

  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // Now add the atom on release.
  if (hit.type == Rendering::AtomType) {
    Index uniqueId = uniqueIdForHit(hit);
    if (uniqueId != MaxIndex && toggleAtom(uniqueId)) {
      m_undoMerge.endRun();
      refreshWidget();
      emit drawablesChanged();
    }
  }

  // The event is left unaccepted so that the navigate tool sees the release
  // and clears the drag it started when the press was passed through.
  return nullptr;
}

QUndoCommand* MeasureTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton && !m_atomIds.isEmpty()) {
    m_atomIds.clear();
    m_undoMerge.endRun();
    refreshWidget();
    emit drawablesChanged();
    e->accept();
  }
  return nullptr;
}

template <typename T>
void MeasureTool::createLabels(T* mol, GeometryNode* geo,
                               QVector<Vector3>& positions)
{
  TextProperties atomLabelProp;
  atomLabelProp.setFontFamily(TextProperties::SansSerif);
  atomLabelProp.setAlign(TextProperties::HCenter, TextProperties::VCenter);

  for (int i = 0; i < m_atomIds.size(); ++i) {
    // pruneDeletedAtoms() has already dropped anything that no longer
    // resolves, so every unique id here refers to a live atom.
    typename T::AtomType atom = mol->atomByUniqueId(m_atomIds[i]);
    unsigned char atomicNumber(atom.atomicNumber());
    positions[i] = atom.position3d();

    const unsigned char* color = Elements::color(atomicNumber);
    atomLabelProp.setColorRgb(contrastColor(Vector3ub(color)).data());

    auto* label = new TextLabel3D;
    label->setText(QString("#%1").arg(i + 1).toStdString());
    label->setTextProperties(atomLabelProp);
    label->setAnchor(positions[i].cast<float>());
    label->setRadius(
      static_cast<float>(Elements::radiusCovalent(atomicNumber)) + 0.1f);
    geo->addDrawable(label);
  }
}

template <typename T>
bool MeasureTool::pruneDeletedAtoms(T* mol)
{
  bool pruned = false;
  for (int i = m_atomIds.size() - 1; i >= 0; --i) {
    if (!mol->atomByUniqueId(m_atomIds[i]).isValid()) {
      m_atomIds.remove(i);
      pruned = true;
    }
  }
  return pruned;
}

bool MeasureTool::pruneStaleAtoms()
{
  if (m_molecule)
    return pruneDeletedAtoms(m_molecule);
  if (m_rwMolecule)
    return pruneDeletedAtoms(m_rwMolecule);
  return false;
}

template <typename T>
QVector<Vector3> MeasureTool::atomPositions(T* mol) const
{
  QVector<Vector3> positions(m_atomIds.size());
  for (int i = 0; i < m_atomIds.size(); ++i)
    positions[i] = mol->atomByUniqueId(m_atomIds[i]).position3d();
  return positions;
}

void MeasureTool::draw(Rendering::GroupNode& node)
{
  // Atoms picked earlier may have been deleted since. Their unique ids no
  // longer resolve, so drop them before measuring anything -- atom indices
  // are reused when an atom is removed, so a stale entry would otherwise
  // measure the wrong atom or read past the end of the molecule.
  if (pruneStaleAtoms()) {
    m_undoMerge.endRun();
    refreshWidget();
  }

  if (m_atomIds.isEmpty())
    return;

  auto* geo = new GeometryNode;
  node.addChild(geo);

  // Add labels, extract positions
  QVector<Vector3> positions(m_atomIds.size(), Vector3());
  if (m_molecule)
    createLabels(m_molecule, geo, positions);
  else if (m_rwMolecule)
    createLabels(m_rwMolecule, geo, positions);

  // The panel's rows are computed from these same positions -- see
  // computeGeometry() -- so the overlay and the panel can never disagree.
  const GeometryValues values = computeGeometry(positions);

  QString overlayText;
  QString dihedralLabel = tr("Dihedral:");
  QString angleLabel = tr("Angle:");
  QString distanceLabel = tr("Distance:");
  // Use the longest label size to determine the field width. Negate it to
  // indicate left-alignment.
  int labelWidth = -std::max(
    { dihedralLabel.size(), angleLabel.size(), distanceLabel.size() });
  switch (m_atomIds.size()) {
    case 4:
      overlayText += QString("%1 %L2°\n")
                       .arg(tr("Dihedral:"), labelWidth)
                       .arg(values.dihedral1234, 9, 'f', 3);
      [[fallthrough]];
    case 3:
      overlayText += QString("%1 %L2°")
                       .arg(tr("Angle:"), labelWidth)
                       .arg(values.angle123, 9, 'f', 3);
      if (values.angle234 < 360.0)
        overlayText += QString(" %L1°").arg(values.angle234, 9, 'f', 3);
      overlayText += '\n';
      [[fallthrough]];
    case 2:
      overlayText += QString("%1 %L2 Å")
                       .arg(tr("Distance:"), labelWidth)
                       .arg(values.distance12, 9, 'f', 3);
      if (values.distance23 >= 0.0)
        overlayText += QString(" %L1 Å").arg(values.distance23, 9, 'f', 3);
      if (values.distance34 >= 0.0)
        overlayText += QString(" %L1 Å").arg(values.distance34, 9, 'f', 3);
      [[fallthrough]];
    default:
      break;
  }

  if (overlayText.isEmpty())
    return;

  TextProperties overlayTProp;
  overlayTProp.setFontFamily(TextProperties::Mono);

  Vector3ub color(64, 255, 220);
  if (m_renderer) {
    auto backgroundColor = m_renderer->scene().backgroundColor();
    color = contrastColor(
      Vector3ub(backgroundColor[0], backgroundColor[1], backgroundColor[2]));
  }

  overlayTProp.setColorRgb(color[0], color[1], color[2]);
  overlayTProp.setAlign(TextProperties::HLeft, TextProperties::VBottom);

  auto* label = new TextLabel2D;
  label->setText(overlayText.toStdString());
  label->setTextProperties(overlayTProp);
  label->setRenderPass(Rendering::Overlay2DPass);
  label->setAnchor(Vector2i(10, 10));

  geo->addDrawable(label);
}

void MeasureTool::refreshWidget()
{
  if (!m_widget)
    return;

  // The molecule may have changed atoms out from under the panel since the
  // last refresh (e.g. another tool deleted one) -- moleculeChanged() can
  // call this before draw() gets a chance to prune, so this cannot rely on
  // draw() alone to keep m_atomIds clean.
  if (pruneStaleAtoms())
    m_undoMerge.endRun();

  GeometryValues values;
  if (m_molecule)
    values = computeGeometry(atomPositions(m_molecule));
  else if (m_rwMolecule)
    values = computeGeometry(atomPositions(m_rwMolecule));

  const int count = m_atomIds.size();
  m_widget->setAtomCount(count);
  if (count >= 2)
    m_widget->setValue(MeasureField::Distance12, values.distance12);
  if (count >= 3) {
    m_widget->setValue(MeasureField::Distance23, values.distance23);
    m_widget->setValue(MeasureField::Angle123, values.angle123);
  }
  if (count >= 4) {
    m_widget->setValue(MeasureField::Distance34, values.distance34);
    m_widget->setValue(MeasureField::Angle234, values.angle234);
    m_widget->setValue(MeasureField::Dihedral1234, values.dihedral1234);
  }
}

void MeasureTool::applyEdit(MeasureField field, double value)
{
  using QtGui::FragmentTools;
  using Result = FragmentTools::CoordinateEditResult;

  // Edits only work on the app's normal path, where setMolecule() gave us a
  // QtGui::Molecule to reach an undo stack through. If somehow only the
  // rw-molecule was set, or a row outlived the atoms it measured (e.g. one
  // was deleted right as this arrived), there is nothing safe to apply;
  // just put the panel back the way it was.
  if (!m_molecule || m_atomIds.size() < requiredAtomCount(field)) {
    refreshWidget();
    return;
  }

  auto* undoMolecule = m_molecule->undoMolecule();
  m_undoMerge.beginEdit(static_cast<int>(field));

  Result result = Result::InvalidAtoms;
  switch (field) {
    case MeasureField::Distance12:
      result = FragmentTools::setChainDistance(
        *undoMolecule, { m_atomIds[0], m_atomIds[1] }, value);
      break;
    case MeasureField::Distance23:
      result = FragmentTools::setChainDistance(
        *undoMolecule, { m_atomIds[1], m_atomIds[2] }, value);
      break;
    case MeasureField::Distance34:
      result = FragmentTools::setChainDistance(
        *undoMolecule, { m_atomIds[2], m_atomIds[3] }, value);
      break;
    case MeasureField::Angle123:
      result = FragmentTools::setChainAngle(
        *undoMolecule, { m_atomIds[0], m_atomIds[1], m_atomIds[2] }, value);
      break;
    case MeasureField::Angle234:
      result = FragmentTools::setChainAngle(
        *undoMolecule, { m_atomIds[1], m_atomIds[2], m_atomIds[3] }, value);
      break;
    case MeasureField::Dihedral1234:
      result = FragmentTools::setChainTorsion(
        *undoMolecule,
        { m_atomIds[0], m_atomIds[1], m_atomIds[2], m_atomIds[3] }, value);
      break;
  }

  if (result == Result::Ok) {
    m_undoMerge.recordEdit(static_cast<int>(field));
    if (m_widget)
      m_widget->clearMessage();
    // This runs refreshWidget() synchronously (moleculeChanged() is
    // connected with a direct, same-thread connection), which re-reads
    // every row from the molecule -- including this one, harmlessly, since
    // it now matches the value just applied.
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);
  } else {
    // If beginEdit() undid the previous step in this run, that undo must be
    // put back: it was silent (position-only undo commands don't emit
    // changed()), so leaving it undone would strand the view out of sync
    // with what's on screen and push the user's prior step onto the redo
    // stack instead of leaving it as the current state. cancelEdit() redoes
    // it before ending the run.
    m_undoMerge.cancelEdit();
    if (m_widget)
      m_widget->setMessage(refusalMessage(field, result));
    refreshWidget();
  }
}

void MeasureTool::endEditingRun(MeasureField)
{
  m_undoMerge.endRun();
}

QString MeasureTool::refusalMessage(
  MeasureField field, QtGui::FragmentTools::CoordinateEditResult result) const
{
  using Result = QtGui::FragmentTools::CoordinateEditResult;

  switch (result) {
    case Result::Ok:
      return QString();
    case Result::InvalidAtoms:
      return tr("One of these atoms no longer exists.");
    case Result::InvalidValue:
      return tr("That's not a value this can be set to.");
    case Result::Degenerate:
      switch (field) {
        case MeasureField::Distance12:
        case MeasureField::Distance23:
        case MeasureField::Distance34:
          return tr("These atoms are in the same place, so this distance isn't "
                    "defined.");
        default:
          return tr("These atoms are in a straight line, so this angle isn't "
                    "defined.");
      }
    case Result::Ring: {
      // Only angles and dihedrals can be refused for this reason (ring bond
      // lengths are allowed, matching the bond table). Name the bond whose
      // ring membership blocked the edit: the first bond of the sub-chain
      // for an angle, or the central, axis bond for the dihedral.
      int a = 1;
      int b = 2;
      switch (field) {
        case MeasureField::Angle234:
          a = 2;
          b = 3;
          break;
        case MeasureField::Dihedral1234:
          a = 2;
          b = 3;
          break;
        default:
          break;
      }
      const QString word =
        field == MeasureField::Dihedral1234 ? tr("dihedral") : tr("angle");
      return tr("The bond between #%1 and #%2 is in a ring, so this %3 "
                "can't change without distorting the ring.")
        .arg(a)
        .arg(b)
        .arg(word);
    }
    case Result::NotRigid: {
      // Name the two atoms that would need to move independently: the
      // whole chain's ends for an angle or dihedral (matching the
      // fixed/moving convention in the panel), or the pair for a distance.
      int a = 1;
      int b = 2;
      switch (field) {
        case MeasureField::Distance23:
          a = 2;
          b = 3;
          break;
        case MeasureField::Distance34:
          a = 3;
          b = 4;
          break;
        case MeasureField::Angle123:
          a = 1;
          b = 3;
          break;
        case MeasureField::Angle234:
          a = 2;
          b = 4;
          break;
        case MeasureField::Dihedral1234:
          a = 1;
          b = 4;
          break;
        default:
          break;
      }
      return tr("#%1 and #%2 are connected through the molecule, so this "
                "can't change without distorting it. Try the Manipulate "
                "tool.")
        .arg(a)
        .arg(b);
    }
  }
  return QString();
}

Index MeasureTool::uniqueIdForHit(const Rendering::Identifier& hit) const
{
  if (hit.type != Rendering::AtomType)
    return MaxIndex;

  if (m_molecule) {
    if (hit.index >= m_molecule->atomCount())
      return MaxIndex;
    return m_molecule->atomUniqueId(hit.index);
  }
  if (m_rwMolecule) {
    if (hit.index >= m_rwMolecule->atomCount())
      return MaxIndex;
    return m_rwMolecule->atomUniqueId(hit.index);
  }
  return MaxIndex;
}

bool MeasureTool::toggleAtom(Index uniqueId)
{
  int ind = m_atomIds.indexOf(uniqueId);
  if (ind >= 0) {
    m_atomIds.remove(ind);
    return true;
  }

  if (m_atomIds.size() >= 4)
    return false;

  m_atomIds.push_back(uniqueId);
  return true;
}

} // namespace Avogadro::QtPlugins
