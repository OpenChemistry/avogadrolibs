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

#include <QtWidgets/QAction>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <Eigen/Geometry>

namespace Avogadro {
namespace QtPlugins {

const float ZOOM_SPEED = 0.02f;
const float ROTATION_SPEED = 0.005f;

Navigator::Navigator(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_glWidget(NULL),
    m_renderer(NULL),
    m_pressedButtons(Qt::NoButton),
    m_currentAction(Nothing)
{
  m_activateAction->setText(tr("Navigate"));
  m_activateAction->setIcon(QIcon(":/icons/navigator.png"));
}

Navigator::~Navigator()
{
}

QWidget * Navigator::toolWidget() const
{
  return NULL;
}

QUndoCommand * Navigator::mousePressEvent(QMouseEvent *e)
{
  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();
  e->accept();

  // Figure out what type of navigation has been requested.
  if (e->buttons() & Qt::LeftButton && e->modifiers() == Qt::NoModifier) {
    m_currentAction = Rotation;
  }
  else if (e->buttons() & Qt::MidButton
           || (e->buttons() & Qt::LeftButton
               && e->modifiers() == Qt::ShiftModifier)) {
    m_currentAction = ZoomTilt;
  }
  else if (e->buttons() & Qt::RightButton
           || (e->buttons() & Qt::LeftButton
               && (e->modifiers() == Qt::ControlModifier
                   || e->modifiers() == Qt::MetaModifier))) {
    m_currentAction = Translation;
  }

  return NULL;
}

QUndoCommand * Navigator::mouseReleaseEvent(QMouseEvent *e)
{
  updatePressedButtons(e, true);
  m_lastMousePosition = QPoint();
  e->accept();
  return NULL;
}

QUndoCommand * Navigator::mouseMoveEvent(QMouseEvent *e)
{
  switch (m_currentAction) {
  case Rotation: {
    QPoint delta = e->pos() - m_lastMousePosition;
    const Eigen::Affine3f &modelView =
        m_renderer->camera().modelView();
    Vector3f xAxis = modelView.linear().row(0).transpose().normalized();
    Vector3f yAxis = modelView.linear().row(1).transpose().normalized();
    Vector3f center = m_renderer->scene().center();

    m_renderer->camera().translate(center);
    m_renderer->camera().rotate(
          static_cast<float>(delta.y()) * ROTATION_SPEED, xAxis);
    m_renderer->camera().rotate(
          static_cast<float>(delta.x()) * ROTATION_SPEED, yAxis);
    m_renderer->camera().translate(-center);

    e->accept();
    break;
  }
  case Translation: {
    Vector3f center = m_renderer->scene().center();
    Vector2f fromScreen(m_lastMousePosition.x(), m_lastMousePosition.y());
    Vector2f toScreen(e->localPos().x(), e->localPos().y());
    Vector3f from(m_renderer->camera().unProject(fromScreen, center));
    Vector3f to(m_renderer->camera().unProject(toScreen, center));

    m_renderer->camera().translate(to - from);

    e->accept();
    break;
  }
  case ZoomTilt: {
    QPoint delta = e->pos() - m_lastMousePosition;
    const Eigen::Affine3f &modelView = m_renderer->camera().modelView();
    Vector3f zAxis = modelView.linear().row(2).transpose().normalized();
    Vector3f center = m_renderer->scene().center();

    // Tilt
    m_renderer->camera().translate(-center);
    m_renderer->camera().rotate(
          static_cast<float>(delta.x()) * ROTATION_SPEED, zAxis);
    m_renderer->camera().translate(center);

    // Zoom
    /// @todo Use scale for orthographic projections
    Vector3f transformedCenter = modelView * center;
    float distance = transformedCenter.norm();
    float t = delta.y() * ZOOM_SPEED;
    float u = 2.0f / distance - 1.0f;
    if (t < u)
      t = u;
    m_renderer->camera().preTranslate(transformedCenter * t);
    //m_renderer->camera().scale(delta.y() * ZOOM_SPEED);

    e->accept();
    break;
  }
  default:
    ;
  }

  m_lastMousePosition = e->pos();

  if (e->isAccepted())
    emit updateRequested();

  return NULL;
}

QUndoCommand * Navigator::mouseDoubleClickEvent(QMouseEvent *e)
{
  // Reset
  if (e->button() == Qt::MiddleButton) {
    if (m_glWidget) {
      m_glWidget->resetCamera();
      e->accept();
      emit updateRequested();
    }
  }
  return NULL;
}

QUndoCommand * Navigator::wheelEvent(QWheelEvent *e)
{
  /// @todo Use scale for orthographic projections
  // Zoom
  const Eigen::Affine3f &modelView =
      m_renderer->camera().modelView();
  Vector3f zAxis = modelView.linear().row(2).transpose().normalized();

  if (m_renderer->projection() == Rendering::Perspective)
    m_renderer->camera().translate(zAxis * e->delta() * ZOOM_SPEED);
  else
    m_renderer->camera().scale(e->delta() * ZOOM_SPEED);

  e->accept();
  emit updateRequested();
  return NULL;
}

QUndoCommand * Navigator::keyPressEvent(QKeyEvent *e)
{
  /// @todo
  e->ignore();
  return NULL;
}

QUndoCommand * Navigator::keyReleaseEvent(QKeyEvent *e)
{
  /// @todo
  e->ignore();
  return NULL;
}

inline void Navigator::updatePressedButtons(QMouseEvent *e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}

} // namespace QtPlugins
} // namespace Avogadro
