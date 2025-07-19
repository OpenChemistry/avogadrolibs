/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SelectionTool_H
#define AVOGADRO_QTPLUGINS_SelectionTool_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/pluginlayermanager.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {
class SelectionToolWidget;

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
  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private slots:
  void applyColor(Vector3ub color);
  void applyLayer(int layer);

private:
  void clearAtoms();
  bool selectAtom(QMouseEvent* e, const Index& atom);
  bool addAtom(const Index& atom);
  bool removeAtom(const Index& atom);
  bool toggleAtom(const Index& atom);

  bool shouldClean(QMouseEvent* e);
  void selectLinkedMolecule(QMouseEvent* e, Index atom);

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  mutable SelectionToolWidget* m_toolWidget;
  bool m_drawSelectionBox;
  bool m_doubleClick;
  bool m_initSelectionBox;
  Vector2 m_start;
  Vector2 m_end;
  QtGui::PluginLayerManager m_layerManager;
};

inline void SelectionTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SelectionTool_H
