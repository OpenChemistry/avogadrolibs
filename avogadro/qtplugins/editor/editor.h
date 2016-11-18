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

#ifndef AVOGADRO_QTPLUGINS_EDITOR_H
#define AVOGADRO_QTPLUGINS_EDITOR_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/rendering/primitive.h>


#include <QtCore/QPoint>

namespace Avogadro {
namespace QtPlugins {
class EditorToolWidget;

/**
 * @class Editor editor.h <avogadro/qtplugins/editor/editor.h>
 * @brief The Editor tool extends and modifies molecules.
 * @author David C. Lonie
 */
class Editor : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit Editor(QObject *parent_ = NULL);
  ~Editor();

  QString name() const AVO_OVERRIDE { return tr("Editor tool"); }
  QString description() const AVO_OVERRIDE { return tr("Editor tool"); }
  unsigned char priority() const AVO_OVERRIDE { return 20; }
  QAction * activateAction() const AVO_OVERRIDE { return m_activateAction; }
  QWidget * toolWidget() const AVO_OVERRIDE;

  void setMolecule(QtGui::Molecule *mol) AVO_OVERRIDE
  {
    if (mol)
      m_molecule = mol->undoMolecule();
  }

  void setEditMolecule(QtGui::RWMolecule *mol) AVO_OVERRIDE
  {
    m_molecule = mol;
  }

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
  QUndoCommand * keyPressEvent(QKeyEvent *e) AVO_OVERRIDE;

  void draw(Rendering::GroupNode &node) AVO_OVERRIDE;

private slots:
  void clearKeyPressBuffer() { m_keyPressBuffer.clear(); }

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * @todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent *, bool release);

  /**
   * Reset all state for this tool.
   */
  void reset();

  void emptyLeftClick(QMouseEvent *e);
  void atomLeftClick(QMouseEvent *e);
  void bondLeftClick(QMouseEvent *e);

  void atomRightClick(QMouseEvent *e);
  void bondRightClick(QMouseEvent *e);

  void atomLeftDrag(QMouseEvent *e);

  QAction *m_activateAction;
  QtGui::RWMolecule *m_molecule;
  QtOpenGL::GLWidget *m_glWidget;
  Rendering::GLRenderer *m_renderer;
  EditorToolWidget *m_toolWidget;
  Rendering::Identifier m_clickedObject;
  Rendering::Identifier m_newObject;
  Rendering::Identifier m_bondedAtom;
  Qt::MouseButtons m_pressedButtons;
  QPoint m_clickPosition;
  unsigned char m_clickedAtomicNumber;
  bool m_bondAdded;
  bool m_fixValenceLater;
  QString m_keyPressBuffer;

  Real m_bondDistance;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NAVIGATOR_H
