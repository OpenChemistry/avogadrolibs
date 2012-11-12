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

GLWidget::GLWidget(QWidget *parent_)
  : QGLWidget(parent_),
    m_navigator(this)
{
  setFocusPolicy(Qt::ClickFocus);
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

void GLWidget::mouseDoubleClickEvent(QMouseEvent *e)
{
  e->ignore();
  m_navigator.mouseDoubleClickEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseDoubleClickEvent(e);
}

void GLWidget::mousePressEvent(QMouseEvent *e)
{
  e->ignore();
  m_navigator.mousePressEvent(e);

  // Testing...
  if (e->button() == Qt::LeftButton) {
    Rendering::Primitive::Identifier hit =
        m_renderer.hit(e->pos().x(), e->pos().y());

    if (hit.type == Rendering::Primitive::Atom)
      qDebug("Atom clicked: index=%lu\n", hit.index);
    else if (hit.type == Rendering::Primitive::Bond)
      qDebug("Bond clicked: index=%lu\n", hit.index);
  }

  if (!e->isAccepted())
    QGLWidget::mousePressEvent(e);
}

void GLWidget::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();
  m_navigator.mouseMoveEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseMoveEvent(e);
}

void GLWidget::mouseReleaseEvent(QMouseEvent *e)
{
  e->ignore();
  m_navigator.mouseReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseReleaseEvent(e);
}

void GLWidget::wheelEvent(QWheelEvent *e)
{
  e->ignore();
  m_navigator.wheelEvent(e);

  if (!e->isAccepted())
    QGLWidget::wheelEvent(e);
}

void GLWidget::keyPressEvent(QKeyEvent *e)
{
  e->ignore();
  m_navigator.keyPressEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyPressEvent(e);
}

void GLWidget::keyReleaseEvent(QKeyEvent *e)
{
  e->ignore();
  m_navigator.keyReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyReleaseEvent(e);
}

} // End QtOpenGL namespace
} // End Avogadro namespace
