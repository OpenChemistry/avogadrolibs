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

#include "navigator.h"

#include <avogadro/core/vector.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/scene.h>

#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>
#include <QtWidgets/QAction>

#include <Eigen/Geometry>

namespace Avogadro {
namespace QtPlugins {

const float ZOOM_SPEED = 0.02f;
const float ROTATION_SPEED = 0.005f;

Navigator::Navigator(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_glWidget(nullptr), m_renderer(nullptr),
    m_pressedButtons(Qt::NoButton), m_currentAction(Nothing)
{
  m_activateAction->setText(tr("Navigate"));
  m_activateAction->setIcon(QIcon(":/icons/navigator.png"));
}

Navigator::~Navigator()
{
}

QWidget* Navigator::toolWidget() const
{
  return nullptr;
}

QUndoCommand* Navigator::mousePressEvent(QMouseEvent* e)
{
  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();
  e->accept();

  // Figure out what type of navigation has been requested.
  if (e->buttons() & Qt::LeftButton && e->modifiers() == Qt::NoModifier) {
    m_currentAction = Rotation;
  } else if (e->buttons() & Qt::MidButton ||
             (e->buttons() & Qt::LeftButton &&
              e->modifiers() == Qt::ShiftModifier)) {
    m_currentAction = ZoomTilt;
  } else if (e->buttons() & Qt::RightButton ||
             (e->buttons() & Qt::LeftButton &&
              (e->modifiers() == Qt::ControlModifier ||
               e->modifiers() == Qt::MetaModifier))) {
    m_currentAction = Translation;
  }

  return nullptr;
}

QUndoCommand* Navigator::mouseReleaseEvent(QMouseEvent* e)
{
  updatePressedButtons(e, true);
  m_lastMousePosition = QPoint();
  m_currentAction = Nothing;
  e->accept();
  return nullptr;
}

QUndoCommand* Navigator::mouseMoveEvent(QMouseEvent* e)
{
  switch (m_currentAction) {
    case Rotation: {
      QPoint delta = e->pos() - m_lastMousePosition;
      rotate(m_renderer->scene().center(), delta.y(), delta.x(), 0);
      e->accept();
      break;
    }
    case Translation: {
      Vector2f fromScreen(m_lastMousePosition.x(), m_lastMousePosition.y());
      Vector2f toScreen(e->localPos().x(), e->localPos().y());
      translate(m_renderer->scene().center(), fromScreen, toScreen);
      e->accept();
      break;
    }
    case ZoomTilt: {
      QPoint delta = e->pos() - m_lastMousePosition;
      // Tilt
      rotate(m_renderer->scene().center(), 0, 0, delta.x());
      // Zoom
      zoom(m_renderer->scene().center(), delta.y());
      e->accept();
      break;
    }
    default:;
  }

  m_lastMousePosition = e->pos();

  if (e->isAccepted())
    emit updateRequested();

  return nullptr;
}

QUndoCommand* Navigator::mouseDoubleClickEvent(QMouseEvent* e)
{
  // Reset
  if (e->button() == Qt::MiddleButton) {
    if (m_glWidget) {
      m_glWidget->resetCamera();
      e->accept();
      emit updateRequested();
    }
  }
  return nullptr;
}

QUndoCommand* Navigator::wheelEvent(QWheelEvent* e)
{
  /// @todo Use scale for orthographic projections
  // Zoom
  zoom(m_renderer->scene().center(), e->delta() * 0.1);

  e->accept();
  emit updateRequested();
  return nullptr;
}

QUndoCommand* Navigator::keyPressEvent(QKeyEvent* e)
{
  Vector3f ref = m_renderer->scene().center();
  switch (e->key()) {
    case Qt::Key_Left:
    case Qt::Key_H:
    case Qt::Key_A:
      if (e->modifiers() == Qt::NoModifier ||
          e->modifiers() == Qt::KeypadModifier)
        rotate(ref, 0, -5, 0);
      else if (e->modifiers() == Qt::ShiftModifier)
        rotate(ref, 0, 0, -5);
      else if (e->modifiers() == Qt::ControlModifier)
        translate(ref, -5, 0);
      e->accept();
      break;
    case Qt::Key_Right:
    case Qt::Key_L:
    case Qt::Key_D:
      if (e->modifiers() == Qt::NoModifier ||
          e->modifiers() == Qt::KeypadModifier)
        rotate(ref, 0, 5, 0);
      else if (e->modifiers() == Qt::ShiftModifier)
        rotate(ref, 0, 0, 5);
      else if (e->modifiers() == Qt::ControlModifier)
        translate(ref, 5, 0);
      e->accept();
      break;
    case Qt::Key_Up:
    case Qt::Key_K:
    case Qt::Key_W:
      if (e->modifiers() == Qt::NoModifier ||
          e->modifiers() == Qt::KeypadModifier)
        rotate(ref, -5, 0, 0);
      else if (e->modifiers() == Qt::ShiftModifier)
        zoom(ref, -2);
      else if (e->modifiers() == Qt::ControlModifier)
        translate(ref, 0, -5);
      e->accept();
      break;
    case Qt::Key_Down:
    case Qt::Key_J:
    case Qt::Key_S:
      if (e->modifiers() == Qt::NoModifier ||
          e->modifiers() == Qt::KeypadModifier)
        rotate(ref, 5, 0, 0);
      else if (e->modifiers() == Qt::ShiftModifier)
        zoom(ref, 2);
      else if (e->modifiers() == Qt::ControlModifier)
        translate(ref, 0, 5);
      e->accept();
      break;
    default:
      e->ignore();
  }
  emit updateRequested();
  return nullptr;
}

QUndoCommand* Navigator::keyReleaseEvent(QKeyEvent* e)
{
  /// @todo
  e->ignore();
  return nullptr;
}

inline void Navigator::updatePressedButtons(QMouseEvent* e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

inline void Navigator::rotate(const Vector3f& ref, float x, float y, float z)
{
  const Eigen::Affine3f& modelView = m_renderer->camera().modelView();
  Vector3f xAxis = modelView.linear().row(0).transpose().normalized();
  Vector3f yAxis = modelView.linear().row(1).transpose().normalized();
  Vector3f zAxis = modelView.linear().row(2).transpose().normalized();
  m_renderer->camera().translate(ref);
  m_renderer->camera().rotate(x * ROTATION_SPEED, xAxis);
  m_renderer->camera().rotate(y * ROTATION_SPEED, yAxis);
  m_renderer->camera().rotate(z * ROTATION_SPEED, zAxis);
  m_renderer->camera().translate(-ref);
}

inline void Navigator::zoom(const Vector3f& ref, float d)
{
  const Eigen::Affine3f& modelView = m_renderer->camera().modelView();
  Vector3f transformedCenter = modelView * ref;
  float distance = transformedCenter.norm();
  float t = d * ZOOM_SPEED;
  float u = 2.0f / distance - 1.0f;
  if (t < u)
    t = u;
  if (m_renderer->camera().projectionType() == Rendering::Perspective)
    m_renderer->camera().preTranslate(transformedCenter * t);
  else
    m_renderer->camera().scale(t + 1.0f);
}

inline void Navigator::translate(const Vector3f& ref, float x, float y)
{
  Vector2f fromScreen(0, 0);
  Vector2f toScreen(x, y);
  translate(ref, fromScreen, toScreen);
}

inline void Navigator::translate(const Vector3f& ref, const Vector2f& fromScr,
                                 const Vector2f& toScr)
{
  Vector3f from(m_renderer->camera().unProject(fromScr, ref));
  Vector3f to(m_renderer->camera().unProject(toScr, ref));
  m_renderer->camera().translate(to - from);
}

} // namespace QtPlugins
} // namespace Avogadro
