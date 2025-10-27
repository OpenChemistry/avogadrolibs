/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ALIGNTOOL_H
#define AVOGADRO_QTPLUGINS_ALIGNTOOL_H

#include <avogadro/qtgui/toolplugin.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/primitive.h>

namespace Avogadro::QtPlugins {

/**
 * @class AlignTool aligntool.h
 * <avogadro/qtplugins/aligntool/aligntool.h>
 * @brief The Align Tool class aligns molecules to a frame of reference.
 * @author Geoffrey Hutchison
 */
class AlignTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit AlignTool(QObject* parent_ = nullptr);
  ~AlignTool() override;

  QString name() const override { return tr("Align tool"); }
  QString description() const override
  {
    return tr("Align molecules to a Cartesian axis");
  }
  unsigned char priority() const override { return 90; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;

  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule* mol) override
  {
    if (mol)
      m_molecule = mol->undoMolecule();
  }

  void setEditMolecule(QtGui::RWMolecule* mol) override { m_molecule = mol; }

  void setGLRenderer(Rendering::GLRenderer* renderer) override
  {
    m_renderer = renderer;
  }

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

  void shiftAtomToOrigin(Index atomIndex);
  void alignAtomToAxis(Index atomIndex, int axis);

  bool toggleAtom(const Rendering::Identifier& atom);

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  /**
   * Called by the app to tell the tool to register commands.
   * If the tool has commands, it should emit the registerCommand signals.
   */
  void registerCommands() override;

public Q_SLOTS:
  void axisChanged(int axis);
  void alignChanged(int align);
  void align();

private:
  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  Rendering::GLRenderer* m_renderer;
  QVector<Rendering::Identifier> m_atoms;

  int m_axis;
  int m_alignType;

  mutable QWidget* m_toolWidget;

private Q_SLOTS:
  void toolWidgetDestroyed();
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTOPENGL_ALIGNTOOL_H
