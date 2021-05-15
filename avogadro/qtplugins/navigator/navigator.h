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

#include <avogadro/core/vector.h>

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace

namespace Avogadro {
namespace QtPlugins {

/**
 * @class Navigator navigator.h <avogadro/qtplugins/navigator/navigator.h>
 * @brief The Navigator tool updates the camera in response to user input.
 * @author Allison Vacanti
 */
class Navigator : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit Navigator(QObject* parent_ = nullptr);
  ~Navigator() override;

  QString name() const override { return tr("Navigate tool"); }
  QString description() const override { return tr("Navigate tool"); }
  unsigned char priority() const override { return 10; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setMolecule(QtGui::Molecule* mol) override { m_molecule = mol; }
  void setGLWidget(QtOpenGL::GLWidget* widget) override { m_glWidget = widget; }
  void setGLRenderer(Rendering::GLRenderer* renderer) override
  {
    m_renderer = renderer;
  }

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;
  QUndoCommand* wheelEvent(QWheelEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;
  QUndoCommand* keyReleaseEvent(QKeyEvent* e) override;

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent*, bool release);

  void rotate(const Vector3f& ref, float x, float y, float z);
  void zoom(const Vector3f& ref, float d);
  void translate(const Vector3f& ref, float x, float y);
  void translate(const Vector3f& ref, const Vector2f& from, const Vector2f& to);

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  QtOpenGL::GLWidget* m_glWidget;
  Rendering::GLRenderer* m_renderer;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_lastMousePosition;

  enum ToolAction
  {
    Nothing = 0,
    Rotation,
    Translation,
    ZoomTilt,
    Zoom
  };
  ToolAction m_currentAction;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NAVIGATOR_H
