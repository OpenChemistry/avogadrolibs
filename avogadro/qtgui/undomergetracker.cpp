/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "undomergetracker.h"

#include <QObject>
#include <QUndoStack>

namespace Avogadro {
namespace QtGui {

UndoMergeTracker::UndoMergeTracker(QUndoStack* stack)
  : m_stack(nullptr), m_fieldId(-1), m_command(nullptr), m_index(-1),
    m_editing(false), m_undone(false)
{
  setUndoStack(stack);
}

UndoMergeTracker::~UndoMergeTracker()
{
  disconnectFromStack();
}

void UndoMergeTracker::disconnectFromStack()
{
  QObject::disconnect(m_connection);
  m_connection = QMetaObject::Connection();
}

QUndoStack* UndoMergeTracker::undoStack() const
{
  return m_stack.data();
}

void UndoMergeTracker::setUndoStack(QUndoStack* stack)
{
  if (m_stack == stack)
    return;

  endRun();
  disconnectFromStack();

  m_stack = stack;
  if (!m_stack.isNull()) {
    // The context object (m_stack itself) ties the connection's lifetime to
    // the stack, so a stack destroyed without setUndoStack(nullptr) being
    // called first can't leave a dangling callback. It is also explicitly
    // disconnected above whenever this tracker points somewhere else, or is
    // itself destroyed.
    m_connection = QObject::connect(m_stack, &QUndoStack::indexChanged, m_stack,
                                    [this](int) {
                                      // A change that happens *because* of
                                      // beginEdit()'s own undo(), or the
                                      // caller's push right after it, is
                                      // expected -- see the class comment.
                                      // Anything else, including a change
                                      // between one recordEdit() and the next
                                      // beginEdit(), means some other edit
                                      // touched the stack, so this run can no
                                      // longer safely merge into it.
                                      if (!m_editing)
                                        endRun();
                                    });
  }
}

bool UndoMergeTracker::beginEdit(int fieldId)
{
  m_editing = true;
  m_undone = false;

  if (m_stack.isNull() || fieldId != m_fieldId || m_command == nullptr) {
    m_fieldId = fieldId;
    m_command = nullptr;
    m_index = -1;
    return false;
  }

  // Second line of defense behind the indexChanged watch above: merging is
  // only safe while the recorded command is still exactly the top of the
  // stack.
  if (m_stack->index() != m_index || m_stack->index() != m_stack->count() ||
      m_stack->command(m_index - 1) != m_command) {
    m_command = nullptr;
    m_index = -1;
    return false;
  }

  m_stack->undo();
  m_undone = true;
  return true;
}

void UndoMergeTracker::recordEdit(int fieldId)
{
  m_fieldId = fieldId;
  if (!m_stack.isNull() && m_stack->index() == m_stack->count() &&
      m_stack->index() > 0) {
    m_index = m_stack->index();
    m_command = m_stack->command(m_index - 1);
  } else {
    m_index = -1;
    m_command = nullptr;
  }
  m_editing = false;
  m_undone = false;
}

void UndoMergeTracker::endRun()
{
  m_fieldId = -1;
  m_command = nullptr;
  m_index = -1;
  m_editing = false;
  m_undone = false;
}

void UndoMergeTracker::cancelEdit()
{
  if (m_undone && !m_stack.isNull())
    m_stack->redo();
  endRun();
}

} // namespace QtGui
} // namespace Avogadro
