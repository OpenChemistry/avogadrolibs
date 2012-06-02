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

#include "glwidget.h"

#include <avogadro/rendering/camera.h>

#include <iostream>
#include <Eigen/Geometry>

#include <QtCore/QDebug>
#include <QtGui/QMouseEvent>

namespace Avogadro {
namespace QtOpenGL {

GLWidget::GLWidget(QWidget *parent_) : QGLWidget(parent_)
{
}

GLWidget::~GLWidget()
{
}

void GLWidget::resetCamera()
{
  m_renderer.resetCamera();
  update();
}

void GLWidget::initializeGL()
{
  m_renderer.initialize();
  if (!m_renderer.isValid()) {
    qDebug() << "Error initializing: " << m_renderer.error().c_str();
  }
}

void GLWidget::resizeGL(int width_, int height_)
{
  m_renderer.resize(width_, height_);
}

void GLWidget::paintGL()
{
  m_renderer.render();
}

void GLWidget::mouseDoubleClickEvent(QMouseEvent *)
{
  resetCamera();
}

void GLWidget::mousePressEvent(QMouseEvent *event_)
{
  if (event_->button() == Qt::LeftButton) {
    Vector2f position(event_->pos().x(), event_->pos().y());
    Vector3f result = m_renderer.camera().unProject(position);
    m_renderer.scene().addSphere(result, Vector3ub(255, 255, 255), 1.0);
    update();
  }
}

void GLWidget::mouseMoveEvent(QMouseEvent *)
{
}

void GLWidget::mouseReleaseEvent(QMouseEvent *)
{
}

void GLWidget::wheelEvent(QWheelEvent *)
{
  m_renderer.camera().rotate(0.1, Vector3f(1, 0, 0));
  update();
}

} // End QtOpenGL namespace
} // End Avogadro namespace
