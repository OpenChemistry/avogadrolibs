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

#ifndef AVOGADRO_QTPLUGINS_MANIPULATOR_H
#define AVOGADRO_QTPLUGINS_MANIPULATOR_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/Qt> // for Qt:: namespace

namespace Avogadro {
namespace QtPlugins {

/**
 * @class Manipulator manipulator.h <avogadro/qtplugins/manipulator/manipulator.h>
 * @brief The Manipulator class manipulates a molecule's geometry.
 * @author David C. Lonie
 */
class Manipulator : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit Manipulator(QObject *parent_ = NULL);
  ~Manipulator();

  QString name() const AVO_OVERRIDE { return tr("Manipulate tool"); }
  QString description() const AVO_OVERRIDE { return tr("Manipulate tool"); }
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE { m_molecule = mol; }
  void setGLWidget(QtOpenGL::GLWidget *widget) AVO_OVERRIDE
  {
    m_glWidget = widget;
  }
  void setGLRenderer(Rendering::GLRenderer *renderer) AVO_OVERRIDE
  {
    m_renderer = renderer;
  }

  QUndoCommand * mousePressEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseReleaseEvent(QMouseEvent *e) AVO_OVERRIDE;
  QUndoCommand * mouseMoveEvent(QMouseEvent *e) AVO_OVERRIDE;

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * \todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent *, bool release);

  void resetObject() { m_object = Rendering::Identifier(); }

  QAction *m_activateAction;
  QtGui::Molecule *m_molecule;
  QtOpenGL::GLWidget *m_glWidget;
  Rendering::GLRenderer *m_renderer;
  Rendering::Identifier m_object;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_lastMousePosition;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_MANIPULATOR_H
