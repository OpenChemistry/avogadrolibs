/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LABELEDITOR_H
#define AVOGADRO_QTPLUGINS_LABELEDITOR_H

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtgui/toolplugin.h>

namespace Avogadro::QtPlugins {

class LabelEditor : public QtGui::ToolPlugin
{
  Q_OBJECT
  Q_PROPERTY(qsizetype pickedAtomIndex READ pickedAtomIndex NOTIFY atomPickedChanged)
  Q_PROPERTY(QString pickedLabel READ pickedLabel NOTIFY atomPickedChanged)
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
    setEditMolecule(mol ? mol->undoMolecule() : nullptr);
  }

  void setEditMolecule(QtGui::RWMolecule* mol) override
  {
    if (m_molecule != mol) {
      m_selectedAtom.reset();
      m_text.clear();
    }
    m_molecule = mol;
  }

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
  qsizetype pickedAtomIndex() const;
  QString pickedLabel() const { return m_text; }
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

signals:
  void atomPickedChanged();

private:
  bool atomPicked() const { return m_selectedAtom.isValid(); }
  void save();

  QAction* m_activateAction;
  QtGui::RWMolecule* m_molecule;
  QtOpenGL::GLWidget* m_glWidget;
  Rendering::GLRenderer* m_renderer;
  QtGui::RWMolecule::PersistentAtomType m_selectedAtom;
  QString m_text;
};

} // namespace Avogadro::QtPlugins

#endif
