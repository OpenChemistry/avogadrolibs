/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "measuretool.h"

#include <avogadro/qtgui/commandregistry.h>

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
#include <QtCore/QMetaType>
#include <QtCore/QVariant>
#include <QtGui/QGuiApplication>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
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
  registerMeasureCommands();
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

QUndoCommand* MeasureTool::keyPressEvent(QKeyEvent* e)
{
  // Escape resets the atom list, like a double-click. Escape inside the
  // panel's spin boxes is handled by the widget and never reaches the tool.
  if (e->key() == Qt::Key_Escape && e->modifiers() == Qt::NoModifier &&
      !m_atomIds.isEmpty()) {
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
        case MeasureField::Dihedral1234:
          return tr("Three of these atoms are in a straight line, so this "
                    "dihedral isn't defined.");
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
      // Whole sentences, not a spliced-in "angle"/"dihedral": translations
      // need to reword around the noun, not just swap it.
      if (field == MeasureField::Dihedral1234)
        return tr("The bond between #%1 and #%2 is in a ring, so this "
                  "dihedral can't change without distorting the ring.")
          .arg(a)
          .arg(b);
      return tr("The bond between #%1 and #%2 is in a ring, so this angle "
                "can't change without distorting the ring.")
        .arg(a)
        .arg(b);
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

namespace {

/// The "value" option of an edit command for @p atomCount atoms (2 = distance,
/// 3 = angle, 4 = dihedral).
QtGui::CommandArgumentSpec editValueSpec(int atomCount)
{
  using QtGui::CommandArgumentSpec;

  // Match the panel's spin box ranges. A distance outside the supported
  // range would stack atoms or fling them out of the universe (the fuzzer
  // found values that overflowed to infinity), and an angle outside 0-180
  // degrees lands on the supplement. Dihedrals wrap, so any finite value is
  // meaningful.
  CommandArgumentSpec value =
    CommandArgumentSpec::real(
      "value", atomCount == 2 ? MeasureTool::tr("The new distance in Å.")
                              : MeasureTool::tr("The new angle in degrees."))
      .withRequired()
      .withUnit(atomCount == 2 ? QStringLiteral("Å") : QStringLiteral("°"));
  if (atomCount == 2) {
    value = value.withRange(QtGui::FragmentTools::minimumChainDistance,
                            QtGui::FragmentTools::maximumChainDistance);
  } else if (atomCount == 3) {
    value = value.withRange(0.0, 180.0);
  }
  return value;
}

} // namespace

void MeasureTool::registerMeasureCommands()
{
  using QtGui::CommandArgumentSpec;

  struct Row
  {
    QString name;
    QString description;
    int atomCount;
    QString resultKey;
    bool isEdit;
  };
  const Row rows[] = {
    { "measureDistance",
      tr("Measure the distance in Å between two atoms, given as "
         "zero-based indices: {\"atoms\": [i, j]}. Returns {\"distance\": "
         "…, \"atoms\": [i, j]}."),
      2, "distance", false },
    { "measureAngle",
      tr("Measure the angle in degrees at the middle of three atoms, given "
         "as zero-based indices: {\"atoms\": [i, j, k]}. Returns {\"angle\": "
         "…, \"atoms\": [i, j, k]}."),
      3, "angle", false },
    { "measureDihedral",
      tr("Measure the dihedral angle in degrees (-180 to 180) of four "
         "atoms, given as zero-based indices: {\"atoms\": [i, j, k, l]}. "
         "Returns {\"dihedral\": …, \"atoms\": [i, j, k, l]}."),
      4, "dihedral", false },
    { "editDistance",
      tr("Set the distance in Å between two atoms, given as zero-based "
         "indices: {\"atoms\": [i, j], \"value\": …}; the second atom and "
         "everything bonded to it on that side move. Returns the new "
         "{\"distance\": …, \"atoms\": [i, j]}."),
      2, "distance", true },
    { "editAngle",
      tr("Set the angle in degrees at the middle of three atoms, given as "
         "zero-based indices: {\"atoms\": [i, j, k], \"value\": …}; the "
         "last atom and everything bonded to it on that side move. Returns "
         "the new {\"angle\": …, \"atoms\": [i, j, k]}."),
      3, "angle", true },
    { "editDihedral",
      tr("Set the dihedral angle in degrees of four atoms, given as "
         "zero-based indices: {\"atoms\": [i, j, k, l], \"value\": …}; "
         "the last atom and everything bonded to it on that side move. "
         "Returns the new {\"dihedral\": …, \"atoms\": [i, j, k, l]}."),
      4, "dihedral", true },
  };

  for (const Row& row : rows) {
    QtGui::CommandSpec spec;
    spec.name = row.name;
    spec.description = row.description;
    spec.arguments = { CommandArgumentSpec::atomIndices(
                         "atoms", tr("Zero-based atom indices, in chain "
                                     "order."))
                         .withRequired()
                         .withCount(row.atomCount, row.atomCount) };
    if (row.isEdit)
      spec.arguments.push_back(editValueSpec(row.atomCount));

    spec.handler = [this, row](const QtGui::CommandArguments& args) {
      runCommand(row.atomCount, row.resultKey, row.isEdit, args);
    };
    commandRegistry().add(std::move(spec));
  }
}

bool MeasureTool::handleCommand(const QString& command,
                                const QVariantMap& options)
{
  return commandRegistry().handle(command, options, m_molecule);
}

void MeasureTool::runCommand(int requiredCount, const QString& resultKey,
                             bool isEdit, const QtGui::CommandArguments& args)
{
  // requiredCount also doubles as which of distance/angle/dihedral this is
  // (2/3/4 atoms), since that is all computeGeometry() needs to know. The
  // registry has already checked the molecule, the atom indices (exactly
  // requiredCount, in range, distinct) and, for edits, the value and its
  // range.
  QVector<Index> atomIndices;
  for (Index index : args.atoms(QStringLiteral("atoms")))
    atomIndices.push_back(index);

  if (!isEdit) {
    emit commandFinished(QString(), measuredResult(atomIndices, resultKey));
    return;
  }

  const double value = args.real(QStringLiteral("value"));

  using QtGui::FragmentTools;
  using Result = FragmentTools::CoordinateEditResult;

  const QVector<Index> ids = uniqueIdsForIndices(atomIndices);
  auto* undoMolecule = m_molecule->undoMolecule();

  // Make this its own undo step, distinct from whatever the panel's spin
  // boxes might currently be merging: an RPC edit should neither fold into
  // an in-progress panel run nor have a later panel step fold into it.
  m_undoMerge.endRun();

  Result editResult = Result::InvalidAtoms;
  switch (requiredCount) {
    case 2:
      editResult = FragmentTools::setChainDistance(*undoMolecule,
                                                   { ids[0], ids[1] }, value);
      break;
    case 3:
      editResult = FragmentTools::setChainAngle(
        *undoMolecule, { ids[0], ids[1], ids[2] }, value);
      break;
    case 4:
      editResult = FragmentTools::setChainTorsion(
        *undoMolecule, { ids[0], ids[1], ids[2], ids[3] }, value);
      break;
    default:
      break;
  }

  if (editResult != Result::Ok) {
    emit commandFailed(
      rpcRefusalMessage(requiredCount, editResult, atomIndices));
    return;
  }

  // This runs refreshWidget() synchronously (moleculeChanged() is connected
  // with a direct, same-thread connection), exactly as applyEdit() relies
  // on -- so the panel stays correct if it happens to have the same atoms
  // picked.
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Modified);

  // Re-measure rather than echo the requested value: the panel does the
  // same after applyEdit() succeeds, and a caller should see what the
  // molecule actually ended up at rather than what was asked for.
  emit commandFinished(QString(), measuredResult(atomIndices, resultKey));
}

QVector<Index> MeasureTool::uniqueIdsForIndices(
  const QVector<Index>& atomIndices) const
{
  auto* undoMolecule = m_molecule->undoMolecule();
  QVector<Index> ids(atomIndices.size());
  for (int i = 0; i < atomIndices.size(); ++i)
    ids[i] = undoMolecule->atomUniqueId(atomIndices[i]);
  return ids;
}

QVariantMap MeasureTool::measuredResult(const QVector<Index>& atomIndices,
                                        const QString& resultKey) const
{
  QVector<Vector3> positions(atomIndices.size());
  for (int i = 0; i < atomIndices.size(); ++i)
    positions[i] = m_molecule->atomPosition3d(atomIndices[i]);
  const GeometryValues values = computeGeometry(positions);

  QVariantList atomsResult;
  for (Index index : atomIndices)
    atomsResult.append(static_cast<qint64>(index));

  QVariantMap result;
  result[QStringLiteral("atoms")] = atomsResult;
  switch (atomIndices.size()) {
    case 2:
      result[resultKey] = values.distance12;
      break;
    case 3:
      result[resultKey] = values.angle123;
      break;
    case 4:
      result[resultKey] = values.dihedral1234;
      break;
    default:
      break;
  }
  return result;
}

QString MeasureTool::rpcRefusalMessage(
  int requiredCount, QtGui::FragmentTools::CoordinateEditResult result,
  const QVector<Index>& atomIndices) const
{
  using Result = QtGui::FragmentTools::CoordinateEditResult;

  switch (result) {
    case Result::Ok:
      return QString();
    case Result::InvalidAtoms:
      return tr("One of these atoms no longer exists.");
    case Result::InvalidValue:
      switch (requiredCount) {
        case 2:
          return tr("That's not a value this distance can be set to.");
        case 3:
          return tr("That's not a value this angle can be set to.");
        default:
          return tr("That's not a value this dihedral can be set to.");
      }
    case Result::Degenerate:
      // Matches refusalMessage(): neither case names specific atoms.
      return requiredCount == 2
               ? tr("These atoms are in the same place, so this distance "
                    "isn't defined.")
             : requiredCount == 3
               ? tr("These atoms are in a straight line, so this angle "
                    "isn't defined.")
               : tr("Three of these atoms are in a straight line, so "
                    "this dihedral isn't defined.");
    case Result::Ring: {
      // Mirrors refusalMessage(): name the bond whose ring membership
      // blocked the edit -- the first bond of the chain for an angle, or
      // the central, axis bond for a dihedral. Ring bond lengths are
      // always allowed (matching the bond table), so a distance never
      // reaches this case.
      const Index a = requiredCount == 3 ? atomIndices[0] : atomIndices[1];
      const Index b = requiredCount == 3 ? atomIndices[1] : atomIndices[2];
      if (requiredCount == 3)
        return tr("The bond between atoms %1 and %2 is in a ring, so this "
                  "angle can't change without distorting it.")
          .arg(a)
          .arg(b);
      return tr("The bond between atoms %1 and %2 is in a ring, so this "
                "dihedral can't change without distorting it.")
        .arg(a)
        .arg(b);
    }
    case Result::NotRigid: {
      // Mirrors refusalMessage(): name the two atoms that would need to
      // move independently -- the whole chain's ends for an angle or
      // dihedral, or the pair itself for a distance. Both are just the
      // first and last of the given atoms, in every case.
      const Index a = atomIndices.first();
      const Index b = atomIndices.last();
      switch (requiredCount) {
        case 2:
          return tr("Atoms %1 and %2 are connected through the molecule, so "
                    "this distance can't change without distorting it. Try "
                    "the Manipulate tool.")
            .arg(a)
            .arg(b);
        case 3:
          return tr("Atoms %1 and %2 are connected through the molecule, so "
                    "this angle can't change without distorting it. Try the "
                    "Manipulate tool.")
            .arg(a)
            .arg(b);
        default:
          return tr("Atoms %1 and %2 are connected through the molecule, so "
                    "this dihedral can't change without distorting it. Try "
                    "the Manipulate tool.")
            .arg(a)
            .arg(b);
      }
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
