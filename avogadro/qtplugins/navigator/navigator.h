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

#ifndef AVOGADRO_QTPLUGINS_NAVIGATOR_H
#define AVOGADRO_QTPLUGINS_NAVIGATOR_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace

namespace Avogadro {
namespace QtPlugins {

/**
 * @class Navigator navigator.h <avogadro/qtplugins/navigator/navigator.h>
 * @brief The Navigator tool updates the camera in response to user input.
 * @author David C. Lonie
 */
class Navigator : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit Navigator(QObject *parent_ = NULL);
  ~Navigator();

  QString name() const AVO_OVERRIDE { return tr("Navigate tool"); }
  QString description() const AVO_OVERRIDE { return tr("Navigate tool"); }
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE { m_molecule = mol; }
  void setGLWidget(QtOpenGL::GLWidget *widget) AVO_OVERRIDE
  {
    m_glWidget = widget;
  }

  QUndoCommand * mousePressEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseReleaseEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseMoveEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseDoubleClickEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * wheelEvent(QWheelEvent *e) AVO_OVERRIDE;
  QUndoCommand * keyPressEvent(QKeyEvent *e) AVO_OVERRIDE;
  QUndoCommand * keyReleaseEvent(QKeyEvent *e) AVO_OVERRIDE;

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent *, bool release);

  QAction *m_activateAction;
  QtGui::Molecule *m_molecule;
  QtOpenGL::GLWidget *m_glWidget;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_lastMousePosition;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NAVIGATOR_H
