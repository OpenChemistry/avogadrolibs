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
    m_editor(this),
    m_manipulator(this),
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

  switch (m_tool) {
  case NavigateTool:
    m_navigator.mouseDoubleClickEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.mouseDoubleClickEvent(e);
    break;
  case EditTool:
    m_editor.mouseDoubleClickEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.mouseDoubleClickEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseDoubleClickEvent(e);
}


void GLWidget::mousePressEvent(QMouseEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.mousePressEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.mousePressEvent(e);
    break;
  case EditTool:
    m_editor.mousePressEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.mousePressEvent(e);

  if (!e->isAccepted())
    QGLWidget::mousePressEvent(e);
}

void GLWidget::mouseMoveEvent(QMouseEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.mouseMoveEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.mouseMoveEvent(e);
    break;
  case EditTool:
    m_editor.mouseMoveEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.mouseMoveEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseMoveEvent(e);
}

void GLWidget::mouseReleaseEvent(QMouseEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.mouseReleaseEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.mouseReleaseEvent(e);
    break;
  case EditTool:
    m_editor.mouseReleaseEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.mouseReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::mouseReleaseEvent(e);
}

void GLWidget::wheelEvent(QWheelEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.wheelEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.wheelEvent(e);
    break;
  case EditTool:
    m_editor.wheelEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.wheelEvent(e);

  if (!e->isAccepted())
    QGLWidget::wheelEvent(e);
}

void GLWidget::keyPressEvent(QKeyEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.keyPressEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.keyPressEvent(e);
    break;
  case EditTool:
    m_editor.keyPressEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.keyPressEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyPressEvent(e);
}

void GLWidget::keyReleaseEvent(QKeyEvent *e)
{
  e->ignore();

  switch (m_tool) {
  case NavigateTool:
    m_navigator.keyReleaseEvent(e);
    break;
  case ManipulateTool:
    m_manipulator.keyReleaseEvent(e);
    break;
  case EditTool:
    m_editor.keyReleaseEvent(e);
    break;
  }

  if (!e->isAccepted())
    m_navigator.keyReleaseEvent(e);

  if (!e->isAccepted())
    QGLWidget::keyReleaseEvent(e);
}

} // End QtOpenGL namespace
} // End Avogadro namespace
