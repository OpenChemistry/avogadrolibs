/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MEASURETOOL_H
#define AVOGADRO_QTPLUGINS_MEASURETOOL_H

#include "measurewidget.h"

#include <avogadro/qtgui/fragmenttools.h>
#include <avogadro/qtgui/toolplugin.h>
#include <avogadro/qtgui/undomergetracker.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/primitive.h>

#include <QtCore/QPoint>
#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief MeasureTool displays distances and angles between selected atoms.
 *
 * Based on the Avogadro 1.x implementation by Donald Ephraim Curtis and Marcus
 * D. Hanwell.
 */
class MeasureTool : public QtGui::ToolPlugin
{
  Q_OBJECT
public:
  explicit MeasureTool(QObject* parent_ = nullptr);
  ~MeasureTool() override;

  QString name() const override { return tr("Measure tool"); }
  QString description() const override { return tr("Measure tool"); }
  unsigned char priority() const override { return 60; }
  QAction* activateAction() const override { return m_activateAction; }
  QWidget* toolWidget() const override;
  void setIcon(bool darkTheme = false) override;

  void setMolecule(QtGui::Molecule*) override;
  void setEditMolecule(QtGui::RWMolecule*) override;
  void setGLRenderer(Rendering::GLRenderer* renderer) override;

  QUndoCommand* mousePressEvent(QMouseEvent* e) override;
  QUndoCommand* mouseMoveEvent(QMouseEvent* e) override;
  QUndoCommand* mouseReleaseEvent(QMouseEvent* e) override;
  QUndoCommand* mouseDoubleClickEvent(QMouseEvent* e) override;

  void draw(Rendering::GroupNode& node) override;

private Q_SLOTS:
  /// A row's spin box was given a new value, by typing or by the arrows or
  /// wheel. Applies it via QtGui::FragmentTools.
  void applyEdit(MeasureField field, double value);

  /// A row's spin box lost focus: end the undo-merge run so the next
  /// arrow/wheel step starts a fresh undo step rather than folding into an
  /// old one.
  void endEditingRun(MeasureField field);

  /// The measured molecule changed for some other reason (another tool, a
  /// file load, undo/redo): refresh the panel to match.
  void moleculeChanged(unsigned int change);

  void widgetDestroyed();

private:
  bool toggleAtom(Index uniqueId);

  /**
   * Resolve the picked atom to the persistent unique id the molecule keeps
   * for it, or MaxIndex if it cannot be resolved.
   */
  Index uniqueIdForHit(const Rendering::Identifier& hit) const;

  /**
   * Drop measured atoms that have since been deleted from the molecule.
   * Returns true if anything was removed.
   */
  template <typename T>
  bool pruneDeletedAtoms(T* mol);

  /**
   * Drop measured atoms that have since been deleted, whichever of
   * m_molecule/m_rwMolecule is current. Called before reading positions in
   * both draw() and refreshWidget() -- an atom can be deleted by some other
   * tool between one panel refresh and the next, and reading a stale unique
   * id's position is unsafe (AtomTemplate requires isValid() first).
   */
  bool pruneStaleAtoms();

  template <typename T>
  void createLabels(T* mol, Rendering::GeometryNode* geo,
                    QVector<Vector3>& positions);

  /// The current positions of the measured atoms, in click order.
  template <typename T>
  QVector<Vector3> atomPositions(T* mol) const;

  /// Create the panel widget and wire it up, the first time it is needed.
  void ensureWidget();

  /// Push the current atoms and measured values into the panel. Safe to
  /// call before the panel exists (it then does nothing).
  void refreshWidget();

  /// A short, translated explanation of why an edit was refused, naming the
  /// atoms involved by click order (#1, #2, ...).
  QString refusalMessage(
    MeasureField field,
    QtGui::FragmentTools::CoordinateEditResult result) const;

  QAction* m_activateAction;
  QtGui::Molecule* m_molecule;
  QtGui::RWMolecule* m_rwMolecule;
  Rendering::GLRenderer* m_renderer;
  /// Persistent unique ids of the measured atoms, not atom indices: indices
  /// are invalidated whenever an atom is added to or removed from the
  /// molecule.
  QVector<Index> m_atomIds;
  QPoint m_pressPosition;
  bool m_dragged;

  MeasureWidget* m_widget;
  /// Collapses consecutive arrow/wheel steps on the same field into a
  /// single undo step. Its stack is whichever molecule's undo stack is
  /// currently being edited; see setMolecule().
  QtGui::UndoMergeTracker m_undoMerge;
};

inline void MeasureTool::setGLRenderer(Rendering::GLRenderer* renderer)
{
  m_renderer = renderer;
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_MEASURETOOL_H
