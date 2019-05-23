/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "qvtkwidget.h"

#include <QVTKInteractorAdapter.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkNew.h>

#include <QtGui/QSurfaceFormat>

namespace Avogadro {

QVTKGLWidget::QVTKGLWidget(QWidget* parent, Qt::WindowFlags f)
  : QVTKOpenGLWidget(parent, f)
{
  // Set some defaults for our render window.
  vtkNew<vtkGenericOpenGLRenderWindow> window;
  SetRenderWindow(window);
  auto glFormat = QVTKOpenGLWidget::defaultFormat();
  glFormat.setSamples(8);
  setFormat(glFormat);
}

QVTKGLWidget::~QVTKGLWidget() = default;

void QVTKGLWidget::setEnableHiDPI(bool) {}
} // namespace Avogadro
