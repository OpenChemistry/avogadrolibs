/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_UNDOMERGETRACKER_H
#define AVOGADRO_QTGUI_UNDOMERGETRACKER_H

#include "avogadroqtguiexport.h"

#include <QtCore/QMetaObject> // for QMetaObject::Connection

class QUndoCommand;
class QUndoStack;

namespace Avogadro {
namespace QtGui {

/**
 * @class UndoMergeTracker undomergetracker.h
 * <avogadro/qtgui/undomergetracker.h>
 * @brief Collapse a run of same-field edits, each pushed as its own undo
 * command, into a single undo step.
 *
 * Dragging a spin box's arrows or scrolling its wheel calls back once per
 * step, and each call pushes a fresh absolute-value command (that is how
 * FragmentTools::setChain*() works: it pushes a merge-mode macro, and
 * QUndoStack never merges macros with each other). Left alone, five arrow
 * presses would need five presses of Ctrl+Z to undo. This tracker instead
 * has the caller undo the previous step before pushing the next one, so the
 * whole run collapses to the value it started from.
 *
 * The tracker never touches the stack itself except via beginEdit()'s call
 * to QUndoStack::undo() and cancelEdit()'s call to QUndoStack::redo(); it
 * only decides *whether* to call them. A caller edits a field like this:
 *
 * @code
 * tracker.beginEdit(fieldId);         // undoes the previous step, if merging
 * if (pushANewCommandFor(fieldId))
 *   tracker.recordEdit(fieldId);      // remember it, in case of a next step
 * else
 *   tracker.cancelEdit();             // put back what beginEdit() undid
 * @endcode
 *
 * A run ends -- so the next edit starts a fresh undo step -- whenever
 * endRun() or cancelEdit() is called, whenever beginEdit() is called for a
 * different field, or whenever anything else changes the stack (a push,
 * undo or redo from elsewhere) between one recordEdit() and the next
 * beginEdit(). That last case is caught by watching
 * QUndoStack::indexChanged() directly rather than only by comparing the
 * remembered command pointer against the stack's current top: a pointer
 * comparison alone can't tell a genuinely unchanged stack from one where an
 * unrelated command happened to be deleted and a new one allocated at the
 * same address, landing the index back where it started (a classic ABA
 * problem). The index/count/pointer check is kept as a second line of
 * defense, but the signal is what actually decides most of the time.
 *
 * Not copyable: it owns a live signal connection tied to a specific
 * QUndoStack.
 */
class AVOGADROQTGUI_EXPORT UndoMergeTracker
{
public:
  explicit UndoMergeTracker(QUndoStack* stack = nullptr);
  ~UndoMergeTracker();

  UndoMergeTracker(const UndoMergeTracker&) = delete;
  UndoMergeTracker& operator=(const UndoMergeTracker&) = delete;

  /// The stack this tracker undoes into. Changing it ends the current run.
  void setUndoStack(QUndoStack* stack);
  QUndoStack* undoStack() const { return m_stack; }

  /**
   * Undo the previous step and return true if @p fieldId continues the run
   * recordEdit() last recorded -- same field, and nothing has pushed,
   * undone or redone on the stack since. Otherwise do nothing and return
   * false, starting a fresh run for @p fieldId.
   *
   * Call this immediately before pushing @p fieldId's new command. Between
   * this call and the matching recordEdit() or cancelEdit(), any stack
   * change this tracker itself observes (its own undo() here, or the
   * caller's push right after) is expected and ignored, rather than read as
   * "something else touched the stack" and ending the run early.
   */
  bool beginEdit(int fieldId);

  /**
   * Record that @p fieldId just pushed the command now on top of the
   * stack, so the next beginEdit() for the same field can undo and replace
   * it. Call this once the edit begun by beginEdit() is known to have
   * succeeded.
   */
  void recordEdit(int fieldId);

  /**
   * Stop merging: the next beginEdit(), even for the same field, starts a
   * fresh run. Call this when an edit fails without beginEdit() having
   * undone anything (so there is nothing to put back), on focus-out, or
   * whenever something outside a field edit (such as the set of measured
   * atoms) changes.
   */
  void endRun();

  /**
   * Abandon the edit beginEdit() just began: if it undid the previous step,
   * redo() it to put the stack back exactly as it was, then end the run.
   *
   * Use this -- not endRun() -- when a call to beginEdit() returned true and
   * the edit that followed then failed to push a replacement (e.g. the new
   * value was refused). Leaving the previous step undone would silently
   * discard it: nothing repaints to show the stack reverted, and it would
   * sit on the redo stack instead of being the current state.
   */
  void cancelEdit();

private:
  void disconnectFromStack();

  QUndoStack* m_stack;
  QMetaObject::Connection m_connection;
  int m_fieldId;
  const QUndoCommand* m_command;
  int m_index;
  /// True from the start of beginEdit() until recordEdit(), endRun() or
  /// cancelEdit(), so the index changes those calls themselves cause (our
  /// own undo(), the caller's push, our own redo()) aren't mistaken for an
  /// outside change that should end the run.
  bool m_editing;
  /// True if the beginEdit() currently in progress called undo(); tells
  /// cancelEdit() whether there is anything to redo() back.
  bool m_undone;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_UNDOMERGETRACKER_H
