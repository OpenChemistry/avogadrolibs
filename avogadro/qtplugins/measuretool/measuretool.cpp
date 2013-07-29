/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "measuretool.h"

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/absoluteoverlayquadstrategy.h>
#include <avogadro/rendering/billboardquadstrategy.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/textlabel.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <QtGui/QAction>
#include <QtGui/QIcon>
#include <QtGui/QMouseEvent>

#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace {
const float RAD_TO_DEG_F = 180.f / static_cast<float>(M_PI);
}

using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Rendering::AbsoluteOverlayQuadStrategy;
using Avogadro::Rendering::BillboardQuadStrategy;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel;
using Avogadro::Rendering::TextProperties;

namespace Avogadro {
namespace QtPlugins {

MeasureTool::MeasureTool(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_glWidget(NULL)
{
  m_activateAction->setText(tr("Measure"));
  m_activateAction->setIcon(QIcon(":/icons/measuretool.png"));
}

MeasureTool::~MeasureTool()
{
}

QWidget * MeasureTool::toolWidget() const
{
  return NULL;
}

QUndoCommand * MeasureTool::mousePressEvent(QMouseEvent *e)
{
  if (e->button() != Qt::LeftButton
      || !m_glWidget) {
    return NULL;
  }

  Identifier hit = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

  // If an atom is clicked, accept the event, but don't add it to the atom list
  // until the button is released (this way the user can cancel the click by
  // moving off the atom, and the click won't get passed to the default tool).
  if (hit.type == Rendering::AtomType)
    e->accept();

  return NULL;
}

QUndoCommand * MeasureTool::mouseReleaseEvent(QMouseEvent *e)
{
  // If the click is released on an atom, add it to the list
  if (e->button() != Qt::LeftButton
      || !m_glWidget) {
    return NULL;
  }

  Identifier hit = m_glWidget->renderer().hit(e->pos().x(), e->pos().y());

  // Now add the atom on release.
  if (hit.type == Rendering::AtomType) {
    if (toggleAtom(hit))
      emit drawablesChanged();
    e->accept();
  }

  return NULL;
}

QUndoCommand *MeasureTool::mouseDoubleClickEvent(QMouseEvent *e)
{
  // Reset the atom list
  if (e->button() == Qt::LeftButton
      && !m_atoms.isEmpty()) {
    m_atoms.clear();
    emit drawablesChanged();
    e->accept();
  }
  return NULL;
}

void MeasureTool::draw(Rendering::GroupNode &node)
{
  if (m_atoms.size() == 0)
    return;

  GeometryNode *geo = new GeometryNode;
  node.addChild(geo);

  TextProperties atomLabelProp;
  atomLabelProp.setBold(true);
  atomLabelProp.setPointSize(8);
  atomLabelProp.setFontFamily(TextProperties::SansSerif);
  atomLabelProp.setAlign(TextProperties::HCenter, TextProperties::VCenter);

  // Add labels, extract positions
  QVector<Vector3> positions(m_atoms.size(), Vector3());
  for (int i = 0; i < m_atoms.size(); ++i) {
    Identifier &ident = m_atoms[i];
    Q_ASSERT(ident.type == Rendering::AtomType);
    Q_ASSERT(ident.molecule != NULL);
    Core::Atom atom = ident.molecule->atom(ident.index);
    Q_ASSERT(atom.isValid());
    unsigned char atomicNumber(atom.atomicNumber());
    positions[i] = atom.position3d();

    const unsigned char *color = Elements::color(atomicNumber);
    atomLabelProp.setColorRgb(contrastingColor(Vector3ub(color)).data());


    BillboardQuadStrategy *billboard(new BillboardQuadStrategy);
    billboard->setRadius(Elements::radiusCovalent(atomicNumber));
    billboard->setAnchor(positions[i].cast<float>());
    billboard->setAlign(BillboardQuadStrategy::HCenter,
                        BillboardQuadStrategy::VCenter);

    TextLabel *label = new TextLabel;
    label->setString(QString("#%1").arg(i + 1).toStdString());
    label->setQuadPlacementStrategy(billboard);
    label->setTextProperties(atomLabelProp);
    label->setRenderPass(Rendering::TranslucentPass);

    geo->addDrawable(label);
  }

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
  case 3:
    v2 = positions[2] - positions[1];
    v2Norm = v2.norm();
  case 2:
    v1 = positions[1] - positions[0];
    v1Norm = v1.norm();
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
    overlayText += QString("%1 %L2\n")
        .arg(tr("Dihedral:"), labelWidth)
        .arg(dihedralAngle(v1, v2, v3), 10, 'f', 5);
    angle23 = std::acos((-v2).dot(v3) / (v2Norm * v3Norm)) * RAD_TO_DEG_F;
    // fall through
  case 3:
    angle12 = std::acos((-v1).dot(v2) / (v1Norm * v2Norm)) * RAD_TO_DEG_F;
    overlayText += QString("%1 %L2 %L3\n")
        .arg(tr("Angles:"), labelWidth)
        .arg(angle12, 10, 'f', 5)
        .arg(angle23 < 360.f ? QString::number(angle23, 'f', 5)
                             : QString(), 10);
    // fall through
  case 2:
    overlayText += QString("%1 %L2 %L3 %L4")
        .arg(tr("Distance:"), labelWidth)
        .arg(v1Norm, 10, 'f', 5)
        .arg(v2Norm >= 0.f ? QString::number(v2Norm, 'f', 5) : QString(), 10)
        .arg(v3Norm >= 0.f ? QString::number(v3Norm, 'f', 5) : QString(), 10);
  default:
    break;
  }

  if (overlayText.isEmpty())
    return;

  TextProperties overlayTProp;
  overlayTProp.setPointSize(8);
  overlayTProp.setFontFamily(TextProperties::Mono);
  overlayTProp.setBold(true);
  overlayTProp.setColorRgb(64, 255, 220);

  AbsoluteOverlayQuadStrategy *overlay = new AbsoluteOverlayQuadStrategy;
  overlay->setAlign(AbsoluteOverlayQuadStrategy::HLeft,
                    AbsoluteOverlayQuadStrategy::VBottom);
  overlay->setAnchor(Vector2i(10, 10));

  TextLabel *label = new TextLabel;
  label->setString(overlayText.toStdString());
  label->setTextProperties(overlayTProp);
  label->setRenderPass(Rendering::OverlayPass);
  label->setQuadPlacementStrategy(overlay);

  geo->addDrawable(label);
}

inline Vector3ub MeasureTool::contrastingColor(const Vector3ub &rgb) const
{
  // If we're far 'enough' (+/-32) away from 128, just invert the component.
  // If we're close to 128, inverting the color will end up too close to the
  // input -- adjust the component before inverting.
  const unsigned char minVal = 32;
  const unsigned char maxVal = 223;
  Vector3ub result;
  for (size_t i = 0; i < 3; ++i) {
    unsigned char input = rgb[i];
    if (input > 160 || input < 96)
      result[i] = 255 - input;
    else
      result[i] = 255 - (input / 4);

    // Clamp to 32-->223 to prevent pure black/white
    result[i] = std::min(maxVal, std::max(minVal, result[i]));
  }

  return result;
}

float MeasureTool::dihedralAngle(const Vector3 &b1, const Vector3 &b2,
                                const Vector3 &b3) const
{
  // See http://math.stackexchange.com/questions/47059/
  // how-do-i-calculate-a-dihedral-angle-given-cartesian-coordinates
  // for description of algorithm
  const Vector3 n1 = b1.cross(b2).normalized();
  const Vector3 n2 = b2.cross(b3).normalized();
  const Vector3 m1 = n1.cross(b2.normalized());
  const Real x(n1.dot(n2));
  const Real y(m1.dot(n2));
  return static_cast<float>(std::atan2(y, x)) * RAD_TO_DEG_F;
}

bool MeasureTool::toggleAtom(const Rendering::Identifier &atom)
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

} // namespace QtPlugins
} // namespace Avogadro
