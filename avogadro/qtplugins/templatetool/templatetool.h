/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_TEMPLATE_H
#define AVOGADRO_QTPLUGINS_TEMPLATE_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>

namespace Avogadro {
namespace QtPlugins {
class TemplateToolWidget;

/**
 * @class TemplateTool templatetool.h
 <avogadro/qtplugins/templatetool/templatetool.h>
 * @brief The Template tool inserts fragments, including metal centers.
 * @author Geoffrey R. Hutchison, Aritz, Erkiaga

 */
class TemplateTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit TemplateTool(QObject* parent_ = NULL);
  ~TemplateTool() override;

  QString name() const override { return tr("Template tool"); }
  QString description() const override { return tr("Template tool"); }
  unsigned char priority() const override { return 21; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;
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

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* keyPressEvent(QKeyEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private slots:
  void clearKeyPressBuffer() { m_keyPressBuffer.clear(); }

private:
  /**
   * Update the currently pressed buttons, accounting for modifier keys.
   * @todo Account for modifier keys.
   */
  void updatePressedButtons(QMouseEvent*, bool release);

  /**
   * Reset all state for this tool.
   */
  void reset();

  void emptyLeftClick(QMouseEvent* e);
  void atomLeftClick(QMouseEvent* e);
  void bondLeftClick(QMouseEvent* e);

  void atomRightClick(QMouseEvent* e);
  void bondRightClick(QMouseEvent* e);

  void atomLeftDrag(QMouseEvent* e);

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  QtOpenGL::GLWidget* m_glWidget;
  Rendering::GLRenderer* m_renderer;
  TemplateToolWidget* m_toolWidget;
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
