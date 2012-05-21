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

#ifndef AVOGADRO_QTOPENGL_GLWIDGET_H
#define AVOGADRO_QTOPENGL_GLWIDGET_H

#include "avogadroqtopenglexport.h"

#include <avogadro/rendering/glrenderer.h>

#include <QtOpenGL/QGLWidget>

namespace Avogadro {
namespace QtOpenGL {

class AVOGADROQTOPENGL_EXPORT GLWidget : public QGLWidget
{
  Q_OBJECT

public:
  GLWidget(QWidget *parent = 0);
  ~GLWidget();

  Rendering::GLRenderer& renderer() { return m_renderer; }

protected:
  /// This is where the GL context is initialized.
  void initializeGL();

  /// Take care of resizing the context.
  void resizeGL(int width, int height);

  /// Main entry point for all GL rendering.
  void paintGL();

protected:
  void mouseDoubleClickEvent(QMouseEvent *);
  void mousePressEvent(QMouseEvent *);
  void wheelEvent(QWheelEvent *);

private:
  Rendering::GLRenderer m_renderer;
};

} // End QtOpenGL namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTOPENGL_GLWIDGET_H
