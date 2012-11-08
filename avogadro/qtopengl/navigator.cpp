/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "navigator.h"

#include "glwidget.h"

#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/scene.h>

#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <Eigen/Geometry>

namespace Avogadro {
namespace QtOpenGL {

const float ZOOM_SPEED = 0.02;
const float ROTATION_SPEED = 0.005;

Navigator::Navigator(GLWidget *widget)
  : m_glWidget(widget)
{
}

Navigator::~Navigator()
{
}

void Navigator::mousePressEvent(QMouseEvent *e)
{
  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();
  e->accept();
}

void Navigator::mouseReleaseEvent(QMouseEvent *e)
{
  updatePressedButtons(e, true);
  m_lastMousePosition = QPoint();
  e->accept();
}

void Navigator::mouseMoveEvent(QMouseEvent *e)
{
  // Rotate
  if (m_pressedButtons & Qt::LeftButton) {
    QPoint delta = e->pos() - m_lastMousePosition;
    const Eigen::Affine3f &modelView =
        m_glWidget->renderer().camera().modelView();
    Vector3f xAxis = modelView.linear().row(0).transpose().normalized();
    Vector3f yAxis = modelView.linear().row(1).transpose().normalized();
    Vector3f center = m_glWidget->renderer().scene().center();

    m_glWidget->renderer().camera().translate(-center);
    m_glWidget->renderer().camera().rotate(delta.y() * ROTATION_SPEED, xAxis);
    m_glWidget->renderer().camera().rotate(delta.x() * ROTATION_SPEED, yAxis);
    m_glWidget->renderer().camera().translate(center);

    m_glWidget->update();
    e->accept();
  }
  // Translate
  else if (m_pressedButtons & Qt::RightButton) {
    Vector3f center = m_glWidget->renderer().scene().center();
    Vector2f fromScreen(m_lastMousePosition.x(), m_lastMousePosition.y());
    Vector2f toScreen(e->posF().x(), e->posF().y());
    Vector3f from(m_glWidget->renderer().camera().unProject(fromScreen, center));
    Vector3f to(m_glWidget->renderer().camera().unProject(toScreen, center));

    m_glWidget->renderer().camera().translate(to-from);

    m_glWidget->update();
    e->accept();
  }
  // Tilt/zoom
  else if (m_pressedButtons & Qt::MiddleButton) {
    QPoint delta = e->pos() - m_lastMousePosition;
    const Eigen::Affine3f &modelView =
        m_glWidget->renderer().camera().modelView();
    Vector3f zAxis = modelView.linear().row(2).transpose().normalized();
    Vector3f center = m_glWidget->renderer().scene().center();

    // Tilt
    m_glWidget->renderer().camera().translate(-center);
    m_glWidget->renderer().camera().rotate(delta.x() * ROTATION_SPEED, zAxis);
    m_glWidget->renderer().camera().translate(center);

    // Zoom
    /// @todo Use scale for orthographic projections
    m_glWidget->renderer().camera().translate(delta.y() * ZOOM_SPEED * zAxis);

    m_glWidget->update();
    e->accept();
  }

  m_lastMousePosition = e->pos();
}

void Navigator::mouseDoubleClickEvent(QMouseEvent *e)
{
  // Reset
  if (e->button() == Qt::LeftButton) {
    m_glWidget->resetCamera();
    e->accept();
  }
}

void Navigator::wheelEvent(QWheelEvent *e)
{
  /// @todo Use scale for orthographic projections
  // Zoom
  const Eigen::Affine3f &modelView =
      m_glWidget->renderer().camera().modelView();
  Vector3f zAxis = modelView.linear().row(2).transpose().normalized();

  m_glWidget->renderer().camera().translate(zAxis * e->delta() * ZOOM_SPEED);

  m_glWidget->update();
  e->accept();
}

void Navigator::keyPressEvent(QKeyEvent *e)
{
  /// @todo
}

void Navigator::keyReleaseEvent(QKeyEvent *e)
{
  /// @todo
}

inline void Navigator::updatePressedButtons(QMouseEvent *e, bool release)
{
  /// @todo Use modifier keys on mac
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();
}


} // namespace QtOpenGL
} // namespace Avogadro
