/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "wasmopenglwindow_p.h"
#include "glwidget.h"

#include <QKeyEvent>
#include <QMouseEvent>
#include <QWheelEvent>

namespace Avogadro::QtOpenGL {

WasmOpenGLWindow::WasmOpenGLWindow(GLWidget* owner)
  : QOpenGLWindow(QOpenGLWindow::NoPartialUpdate), m_owner(owner)
{
}

void WasmOpenGLWindow::initializeGL()
{
  m_owner->initializeGL();
}

void WasmOpenGLWindow::resizeGL(int width, int height)
{
  m_owner->resizeGL(width, height);
}

void WasmOpenGLWindow::paintGL()
{
  m_owner->paintGL();
}

void WasmOpenGLWindow::mouseDoubleClickEvent(QMouseEvent* e)
{
  m_owner->mouseDoubleClickEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::mouseDoubleClickEvent(e);
}

void WasmOpenGLWindow::mousePressEvent(QMouseEvent* e)
{
  m_owner->mousePressEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::mousePressEvent(e);
}

void WasmOpenGLWindow::mouseMoveEvent(QMouseEvent* e)
{
  m_owner->mouseMoveEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::mouseMoveEvent(e);
}

void WasmOpenGLWindow::mouseReleaseEvent(QMouseEvent* e)
{
  m_owner->mouseReleaseEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::mouseReleaseEvent(e);
}

void WasmOpenGLWindow::wheelEvent(QWheelEvent* e)
{
  m_owner->wheelEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::wheelEvent(e);
}

void WasmOpenGLWindow::keyPressEvent(QKeyEvent* e)
{
  m_owner->keyPressEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::keyPressEvent(e);
}

void WasmOpenGLWindow::keyReleaseEvent(QKeyEvent* e)
{
  m_owner->keyReleaseEvent(e);
  if (!e->isAccepted())
    QOpenGLWindow::keyReleaseEvent(e);
}

} // namespace Avogadro::QtOpenGL
