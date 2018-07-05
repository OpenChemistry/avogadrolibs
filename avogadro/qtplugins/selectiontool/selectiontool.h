/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  Adapted from Avogadro 1.x with the following authors' permission:
  Copyright 2007 Donald Ephraim Curtis
  Copyright 2008 Marcus D. Hanwell

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SelectionTool_H
#define AVOGADRO_QTPLUGINS_SelectionTool_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief SelectionTool selects atoms and bonds from the screen.
 */
class SelectionTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit SelectionTool(QObject* parent_ = nullptr);
  ~SelectionTool() override;

  QString name() const override { return tr("Selection tool"); }
  QString description() const override { return tr("Selection tool"); }
  unsigned char priority() const override { return 25; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setMolecule(QtGui::Molecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private:
  bool addAtom(const Rendering::Identifier& atom);

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  QVector<Rendering::Identifier> m_atoms;
  bool m_drawSelectionBox;
  Vector2 m_start;
  Vector2 m_end;
};

inline void SelectionTool::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != mol) {
    m_atoms.clear();
    m_molecule = mol;
  }
}

inline void SelectionTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SelectionTool_H
