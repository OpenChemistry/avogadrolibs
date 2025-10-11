/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LABELEDITOR_H
#define AVOGADRO_QTPLUGINS_LABELEDITOR_H

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/toolplugin.h>

namespace Avogadro {
namespace QtPlugins {

class LabelEditor : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit LabelEditor(QObject* parent_ = nullptr);
  ~LabelEditor() override;

  QString name() const override { return tr("Label editor tool"); }
  QString description() const override { return tr("Label editor tool"); }
  unsigned char priority() const override { return 95; }
  QAction* activateAction() const override { return m_activateAction; }
  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule* mol) override
  {
    if (mol)
      m_molecule = mol->undoMolecule();
  }

  void setEditMolecule(QtGui::RWMolecule* mol) override { m_molecule = mol; }

  void setGLWidget(QtOpenGL::GLWidget* widget) override { m_glWidget = widget; }

  void setGLRenderer(Rendering::GLRenderer* renderer) override
  {
    m_renderer = renderer;
  }

  QWidget* toolWidget() const override { return nullptr; }

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private:
  void save();

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  QtOpenGL::GLWidget* m_glWidget;
  Rendering::GLRenderer* m_renderer;
  bool m_selected;
  QtGui::RWAtom m_selectedAtom;
  QString m_text;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif
