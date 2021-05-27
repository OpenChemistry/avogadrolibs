/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-13 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "manipulator.h"

#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtCore/QDebug>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QAction>

using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using QtGui::RWMolecule;
using Rendering::Identifier;

#define ROTATION_SPEED 0.5

Manipulator::Manipulator(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_pressedButtons(Qt::NoButton),
    m_currentAction(Nothing)
{
  m_activateAction->setText(tr("Manipulate"));
  m_activateAction->setIcon(QIcon(":/icons/manipulator.png"));
}

Manipulator::~Manipulator() {}

QWidget* Manipulator::toolWidget() const
{
  return nullptr;
}

QUndoCommand* Manipulator::mousePressEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return nullptr;

  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();
  Vector2f windowPos(e->localPos().x(), e->localPos().y());
  m_lastMouse3D = m_renderer->camera().unProject(windowPos);

  if (m_molecule) {
    m_molecule->setInteractive(true);
  }

  if (m_pressedButtons & Qt::LeftButton) {
    m_object = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_object.type) {
      case Rendering::AtomType:
        e->accept();
        return nullptr;
      default:
        break;
    }
  }

  return nullptr;
}

QUndoCommand* Manipulator::mouseReleaseEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return nullptr;

  updatePressedButtons(e, true);

  if (m_object.type == Rendering::InvalidType)
    return nullptr;

  if (m_molecule) {
    m_molecule->setInteractive(false);
  }

  switch (e->button()) {
    case Qt::LeftButton:
    case Qt::RightButton:
      resetObject();
      e->accept();
      break;
    default:
      break;
  }

  return nullptr;
}

QUndoCommand* Manipulator::mouseMoveEvent(QMouseEvent* e)
{
  updatePressedButtons(e, false);
  e->ignore();

  const Core::Molecule* mol = &m_molecule->molecule();
  Vector2f windowPos(e->localPos().x(), e->localPos().y());

  if (mol->isSelectionEmpty() && m_object.type == Rendering::AtomType &&
      m_object.molecule == mol) {
    // translate single atom position
    RWAtom atom = m_molecule->atom(m_object.index);
    Vector3f oldPos(atom.position3d().cast<float>());
    Vector3f newPos = m_renderer->camera().unProject(windowPos, oldPos);
    atom.setPosition3d(newPos.cast<double>());
  } else if (!mol->isSelectionEmpty()) {
    // update all selected atoms
    Vector3f newPos = m_renderer->camera().unProject(windowPos);
    Vector3 delta = (newPos - m_lastMouse3D).cast<double>();

    if (m_currentAction == Translation) {
      translate(delta);
    }
    else {
      // get the center of the selected atoms
      Vector3 centroid(0.0, 0.0, 0.0);
      unsigned long selectedAtomCount = 0;
      for (Index i = 0; i < m_molecule->atomCount(); ++i) {
        if (!m_molecule->atomSelected(i))
          continue;

      centroid += m_molecule->atomPosition3d(i);
        selectedAtomCount++;
      }
      if (selectedAtomCount > 0)
        centroid /= selectedAtomCount;

      if (m_currentAction == Rotation) {
        rotate(delta, centroid);
      } else if (m_currentAction == ZoomTilt) {
        tilt(delta, centroid);
      }
    }

    // now that we've moved things, save the position
    m_lastMouse3D = newPos;
  }

  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  e->accept();
  return nullptr;
}

void Manipulator::translate(Vector3 delta)
{
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(i, currentPos + delta.cast<double>());
  }
}

void Manipulator::rotate(Vector3 delta, Vector3 centroid)
{
  // Rotate the selected atoms about the center
  // rotate only selected primitives
  Rendering::Camera* camera = &m_renderer->camera();
  Eigen::Vector3d backTransformX =
    camera->modelView().cast<double>().linear().row(0).transpose().normalized();
  Eigen::Vector3d backTransformY =
    camera->modelView().cast<double>().linear().row(1).transpose().normalized();

  Eigen::Projective3d fragmentRotation;
  fragmentRotation.matrix().setIdentity();
  fragmentRotation.translation() = centroid;
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[1] * ROTATION_SPEED, backTransformX));
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[0] * ROTATION_SPEED, backTransformY));
  fragmentRotation.translate(-centroid);

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(
      i, (fragmentRotation * currentPos.homogeneous()).head<3>());
  }
}

void Manipulator::tilt(Vector3 delta, Vector3 centroid)
{
  // Rotate the selected atoms about the center
  // rotate only selected primitives
  Rendering::Camera* camera = &m_renderer->camera();
  Eigen::Vector3d backTransformZ =
    camera->modelView().cast<double>().linear().row(2).transpose().normalized();

  Eigen::Projective3d fragmentRotation;
  fragmentRotation.matrix().setIdentity();
  fragmentRotation.translation() = centroid;
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[0] * ROTATION_SPEED, backTransformZ));
  fragmentRotation.translate(-centroid);

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(
      i, (fragmentRotation * currentPos.homogeneous()).head<3>());
  }
}

void Manipulator::updatePressedButtons(QMouseEvent* e, bool release)
{
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();

  // check for modifier keys (e.g., Mac)
  if (e->buttons() & Qt::LeftButton && e->modifiers() == Qt::NoModifier) {
    m_currentAction = Translation;
  } else if (e->buttons() & Qt::MidButton ||
             (e->buttons() & Qt::LeftButton &&
              e->modifiers() == Qt::ShiftModifier)) {
    m_currentAction = ZoomTilt;
  } else if (e->buttons() & Qt::RightButton ||
             (e->buttons() & Qt::LeftButton &&
              (e->modifiers() == Qt::ControlModifier ||
               e->modifiers() == Qt::MetaModifier))) {
    m_currentAction = Rotation;
  }
}

} // namespace QtPlugins
} // namespace Avogadro
