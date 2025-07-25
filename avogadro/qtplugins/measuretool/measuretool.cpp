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
    m_molecule(nullptr), m_rwMolecule(nullptr), m_renderer(nullptr)
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
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // If an atom is clicked, accept the event, but don't add it to the atom list
  // until the button is released (this way the user can cancel the click by
  // moving off the atom, and the click won't get passed to the default tool).
  if (hit.type == Rendering::AtomType)
    e->accept();

  return nullptr;
}

QUndoCommand* MeasureTool::mouseReleaseEvent(QMouseEvent* e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton || !m_renderer)
    return nullptr;

  Identifier hit = m_renderer->hit(e->pos().x(), e->pos().y());

  // Now add the atom on release.
  if (hit.type == Rendering::AtomType) {
    if (toggleAtom(hit))
      emit drawablesChanged();
    e->accept();
  }

  return nullptr;
}

QUndoCommand* MeasureTool::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton && !m_atoms.isEmpty()) {
    m_atoms.clear();
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

  for (int i = 0; i < m_atoms.size(); ++i) {
    Identifier& ident = m_atoms[i];
    Q_ASSERT(ident.type == Rendering::AtomType);
    Q_ASSERT(ident.molecule != nullptr);

    typename T::AtomType atom = mol->atom(ident.index);
    Q_ASSERT(atom.isValid());
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

void MeasureTool::draw(Rendering::GroupNode& node)
{
  if (m_atoms.size() == 0)
    return;

  auto* geo = new GeometryNode;
  node.addChild(geo);

  // Add labels, extract positions
  QVector<Vector3> positions(m_atoms.size(), Vector3());
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

  switch (m_atoms.size()) {
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
  int labelWidth = -std::max(std::max(dihedralLabel.size(), angleLabel.size()),
                             distanceLabel.size());
  switch (m_atoms.size()) {
    case 4:
      overlayText +=
        QString("%1 %L2\n")
          .arg(tr("Dihedral:"), labelWidth)
          .arg(tr("%L1°").arg(dihedralAngle(v1, v2, v3), 9, 'f', 3), 9);
      angle23 = bondAngle(v2, v3);
    // fall through
    case 3:
      angle12 = bondAngle(v1, v2);
      overlayText +=
        QString("%1 %L2 %L3\n")
          .arg(tr("Angles:"), labelWidth)
          .arg(tr("%L1°").arg(angle12, 9, 'f', 3), 9)
          .arg(angle23 < 360.f ? tr("%L1°").arg(angle23, 9, 'f', 3) : QString(),
               10);
    // fall through
    case 2:
      overlayText +=
        QString("%1 %L2%L3%L4")
          .arg(tr("Distance:"), labelWidth)
          .arg(tr("%L1 Å").arg(v1Norm, 9, 'f', 3), 9)
          .arg(v2Norm >= 0.f ? tr("%L1 Å").arg(v2Norm, 9, 'f', 3) : QString(),
               9)
          .arg(v3Norm >= 0.f ? tr("%L1 Å").arg(v3Norm, 9, 'f', 3) : QString(),
               9);
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

bool MeasureTool::toggleAtom(const Rendering::Identifier& atom)
{
  int ind = m_atoms.indexOf(atom);
  if (ind >= 0) {
    m_atoms.remove(ind);
    return true;
  }

  if (m_atoms.size() >= 4)
    return false;

  m_atoms.push_back(atom);
  return true;
}

} // namespace Avogadro::QtPlugins
