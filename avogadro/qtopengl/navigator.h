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

#ifndef AVOGADRO_QTOPENGL_NAVIGATOR_H
#define AVOGADRO_QTOPENGL_NAVIGATOR_H

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace

class QKeyEvent;
class QMouseEvent;
class QWheelEvent;

namespace Avogadro {
namespace QtOpenGL {

class GLWidget;

/**
 * @class Navigator navigator.h <avogadro/qtopengl/navigator.h>
 * @brief The Navigator class updates the camera in response to user input.
 */
class Navigator
{
public:
  explicit Navigator(GLWidget *widget);
  ~Navigator();

  /** Respond to user input. */
  void mousePressEvent(QMouseEvent *);

  /** Respond to user input. */
  void mouseReleaseEvent(QMouseEvent *);

  /** Respond to user input. */
  void mouseMoveEvent(QMouseEvent *);

  /** Respond to user input. */
  void mouseDoubleClickEvent(QMouseEvent *);

  /** Respond to user input. */
  void wheelEvent(QWheelEvent *);

  /** Respond to user input. */
  void keyPressEvent(QKeyEvent *);

  /** Respond to user input. */
  void keyReleaseEvent(QKeyEvent *);

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent *, bool release);

  GLWidget *m_glWidget;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_lastMousePosition;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_NAVIGATOR_H
