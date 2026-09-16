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

MeasureTool::MeasureTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_rwMolecule(nullptr), m_renderer(nullptr),
    m_dragged(false)
{
  QString shortcut = tr("Ctrl+8", "control-key 8");
  m_activateAction->setText(tr("Measure"));
  m_activateAction->setToolTip(
    tr("Measure Tool\t(%1)\n\n"
       "Left Mouse:\tSelect up to four Atoms.\n"
       "\tDistances are measured between 1-2 and 2-3\n"
       "\tAngle is measured between 1-3 using 2 as the common point\n"
       "\tDihedral is measured between 1-2-3-4\n"
       "Right Mouse:\tReset the measurements.")
      .arg(shortcut));
  setIcon();
}

MeasureTool::~MeasureTool() {}

void MeasureTool::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/measure_dark.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/measure_light.svg"));
}

QWidget* MeasureTool::toolWidget() const
{
  return nullptr;
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
    if (uniqueId != MaxIndex && toggleAtom(uniqueId))
      emit drawablesChanged();
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

void MeasureTool::draw(Rendering::GroupNode& node)
{
  // Atoms picked earlier may have been deleted since. Their unique ids no
  // longer resolve, so drop them before measuring anything -- atom indices
  // are reused when an atom is removed, so a stale entry would otherwise
  // measure the wrong atom or read past the end of the molecule.
  if (m_molecule)
    pruneDeletedAtoms(m_molecule);
  else if (m_rwMolecule)
    pruneDeletedAtoms(m_rwMolecule);

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

  // Calculate angles and distances
  Vector3 v1;
  Vector3 v2;
  Vector3 v3;
  Real v1Norm = -1.f;
  Real v2Norm = -1.f;
  Real v3Norm = -1.f;

  switch (m_atomIds.size()) {
    case 4:
      v3 = positions[3] - positions[2];
      v3Norm = v3.norm();
      [[fallthrough]];
    case 3:
      v2 = positions[2] - positions[1];
      v2Norm = v2.norm();
      [[fallthrough]];
    case 2:
      v1 = positions[1] - positions[0];
      v1Norm = v1.norm();
      [[fallthrough]];
    default:
      break;
  }

  QString overlayText;
  float angle23 = 361.f;
  float angle12 = 361.f;
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
                       .arg(dihedralAngle(v1, v2, v3), 9, 'f', 3);
      angle23 = bondAngle(v2, v3);
      [[fallthrough]];
    case 3:
      angle12 = bondAngle(v1, v2);
      overlayText += QString("%1 %L2°")
                       .arg(tr("Angle:"), labelWidth)
                       .arg(angle12, 9, 'f', 3);
      if (angle23 < 360.f)
        overlayText += QString(" %L1°").arg(angle23, 9, 'f', 3);
      overlayText += '\n';
      [[fallthrough]];
    case 2:
      overlayText += QString("%1 %L2 Å")
                       .arg(tr("Distance:"), labelWidth)
                       .arg(v1Norm, 9, 'f', 3);
      if (v2Norm >= 0.f)
        overlayText += QString(" %L1 Å").arg(v2Norm, 9, 'f', 3);
      if (v3Norm >= 0.f)
        overlayText += QString(" %L1 Å").arg(v3Norm, 9, 'f', 3);
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
