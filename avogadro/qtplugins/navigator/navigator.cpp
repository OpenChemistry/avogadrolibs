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

#include <QtGui/QAction>
#include <QtGui/QIcon>
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
    m_pressedButtons(Qt::NoButton)
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
  // Rotate
  if (m_pressedButtons & Qt::LeftButton) {
    QPoint delta = e->pos() - m_lastMousePosition;
    const Eigen::Affine3f &modelView =
        m_glWidget->renderer().camera().modelView();
    Vector3f xAxis = modelView.linear().row(0).transpose().normalized();
    Vector3f yAxis = modelView.linear().row(1).transpose().normalized();
    Vector3f center = m_glWidget->renderer().scene().center();

    m_glWidget->renderer().camera().translate(center);
    m_glWidget->renderer().camera().rotate(
          static_cast<float>(delta.y()) * ROTATION_SPEED, xAxis);
    m_glWidget->renderer().camera().rotate(
          static_cast<float>(delta.x()) * ROTATION_SPEED, yAxis);
    m_glWidget->renderer().camera().translate(-center);

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
    m_glWidget->renderer().camera().rotate(
          static_cast<float>(delta.x()) * ROTATION_SPEED, zAxis);
    m_glWidget->renderer().camera().translate(center);

    // Zoom
    /// @todo Use scale for orthographic projections
    m_glWidget->renderer().camera().translate(
          static_cast<float>(delta.y()) * ZOOM_SPEED * zAxis);

    m_glWidget->update();
    e->accept();
  }

  m_lastMousePosition = e->pos();

  return NULL;
}

QUndoCommand * Navigator::mouseDoubleClickEvent(QMouseEvent *e)
{
  // Reset
  if (e->button() == Qt::LeftButton) {
    m_glWidget->resetCamera();
    e->accept();
  }
  return NULL;
}

QUndoCommand * Navigator::wheelEvent(QWheelEvent *e)
{
  /// @todo Use scale for orthographic projections
  // Zoom
  const Eigen::Affine3f &modelView =
      m_glWidget->renderer().camera().modelView();
  Vector3f zAxis = modelView.linear().row(2).transpose().normalized();

  m_glWidget->renderer().camera().translate(
        zAxis * static_cast<float>(e->delta()) * ZOOM_SPEED);

  m_glWidget->update();
  e->accept();
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
