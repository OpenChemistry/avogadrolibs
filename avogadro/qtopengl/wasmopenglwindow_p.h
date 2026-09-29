/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_WASMOPENGLWINDOW_P_H
#define AVOGADRO_QTOPENGL_WASMOPENGLWINDOW_P_H

#include <QtOpenGL/QOpenGLWindow>

namespace Avogadro::QtOpenGL {
class GLWidget;

// QOpenGLWidget is unavailable on WASM. Forward the window's rendering and
// input callbacks to the owning widget embedded in the application layout.
class WasmOpenGLWindow : public QOpenGLWindow
{
public:
  explicit WasmOpenGLWindow(GLWidget* owner);

protected:
  void initializeGL() override;
  void resizeGL(int width, int height) override;
  void paintGL() override;
  void mouseDoubleClickEvent(QMouseEvent* e) override;
  void mousePressEvent(QMouseEvent* e) override;
  void mouseMoveEvent(QMouseEvent* e) override;
  void mouseReleaseEvent(QMouseEvent* e) override;
  void wheelEvent(QWheelEvent* e) override;
  void keyPressEvent(QKeyEvent* e) override;
  void keyReleaseEvent(QKeyEvent* e) override;

private:
  GLWidget* m_owner;
};
} // namespace Avogadro::QtOpenGL

#endif
