/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/undomergetracker.h>

#include <QUndoStack>

using Avogadro::QtGui::UndoMergeTracker;

namespace {

// A minimal absolute-value command, standing in for the commands
// FragmentTools::setChain*() pushes: apply a new value on redo(), restore
// the old one on undo().
class SetValueCommand : public QUndoCommand
{
public:
  SetValueCommand(int* target, int oldValue, int newValue)
    : m_target(target), m_oldValue(oldValue), m_newValue(newValue)
  {
  }

  void redo() override { *m_target = m_newValue; }
  void undo() override { *m_target = m_oldValue; }

private:
  int* m_target;
  int m_oldValue;
  int m_newValue;
};

} // namespace

TEST(UndoMergeTrackerTest, FirstEditOnAFieldDoesNotMerge)
{
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
}

TEST(UndoMergeTrackerTest, ConsecutiveEditsOnSameFieldMergeIntoOneUndoStep)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  // Step 1: 0 -> 1.
  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);
  EXPECT_EQ(value, 1);
  EXPECT_EQ(stack.count(), 1);

  // Step 2: same field, so the tracker undoes step 1 before this is pushed.
  EXPECT_TRUE(tracker.beginEdit(1));
  EXPECT_EQ(value, 0);
  stack.push(new SetValueCommand(&value, 0, 2));
  tracker.recordEdit(1);
  EXPECT_EQ(value, 2);
  EXPECT_EQ(stack.count(), 1);

  // Step 3: same again.
  EXPECT_TRUE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 3));
  tracker.recordEdit(1);
  EXPECT_EQ(value, 3);
  EXPECT_EQ(stack.count(), 1);

  // A single undo (one Ctrl+Z) returns to the value from before the first
  // step, not just the step before this one.
  stack.undo();
  EXPECT_EQ(value, 0);
}

TEST(UndoMergeTrackerTest, EditingADifferentFieldStartsAFreshRun)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  // A different field never merges, even though it is the very next edit.
  EXPECT_FALSE(tracker.beginEdit(2));
  stack.push(new SetValueCommand(&value, 1, 2));
  tracker.recordEdit(2);
  EXPECT_EQ(stack.count(), 2);

  // Undo unwinds one field at a time.
  stack.undo();
  EXPECT_EQ(value, 1);
  stack.undo();
  EXPECT_EQ(value, 0);
}

TEST(UndoMergeTrackerTest, EndRunStopsMergingUntilTheNextRecordedEdit)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  // Focus-out, an atom-list change, or a failed edit all end the run
  // without pushing anything.
  tracker.endRun();

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 1, 2));
  tracker.recordEdit(1);
  EXPECT_EQ(stack.count(), 2);
}

TEST(UndoMergeTrackerTest, AnUnrelatedStackChangeBreaksTheMerge)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  // Something else pushes to the stack without going through the tracker
  // (e.g. an unrelated edit elsewhere in the app).
  stack.push(new SetValueCommand(&value, 1, 5));

  // The command the tracker remembered is no longer the top of the stack,
  // so it must not undo it out from under that other edit.
  EXPECT_FALSE(tracker.beginEdit(1));
  EXPECT_EQ(value, 5);
}

TEST(UndoMergeTrackerTest, UndoingBeforeTheNextEditBreaksTheMerge)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  // An undo from elsewhere (e.g. Ctrl+Z while the field still has focus)
  // moves the stack's index off the recorded command.
  stack.undo();
  EXPECT_EQ(value, 0);

  EXPECT_FALSE(tracker.beginEdit(1));
}

TEST(UndoMergeTrackerTest, SwitchingUndoStacksEndsTheRun)
{
  int value = 0;
  QUndoStack stackA;
  QUndoStack stackB;
  UndoMergeTracker tracker(&stackA);

  EXPECT_FALSE(tracker.beginEdit(1));
  stackA.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  tracker.setUndoStack(&stackB);
  EXPECT_FALSE(tracker.beginEdit(1));
}

// Regression test for an ABA hazard in the old pointer/index-only check: an
// external undo followed by an external push can put the stack's index and
// count back to exactly what recordEdit() saw, and if the deleted command
// happened to be reallocated at the same address, a pointer comparison alone
// could be fooled into undoing someone else's edit. The indexChanged watch
// must catch the external undo the moment it happens -- before the address
// could even be reused -- so this must not depend on the two commands
// actually landing at the same address to prove the fix.
TEST(UndoMergeTrackerTest,
     ExternalUndoThenPushBreaksTheMergeEvenIfIndexMatchesAgain)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1)); // index 1, count 1
  tracker.recordEdit(1);

  // Something else undoes the recorded step (index 0) and then pushes an
  // unrelated command (index 1, count 1 again) -- matching what recordEdit()
  // saw, even though it is a different edit entirely.
  stack.undo();
  stack.push(new SetValueCommand(&value, 0, 9));

  EXPECT_FALSE(tracker.beginEdit(1));
  // Critically, beginEdit() must not have undone the unrelated command it
  // was fooled into thinking was its own.
  EXPECT_EQ(value, 9);
}

TEST(UndoMergeTrackerTest, CancelEditRedoesTheUndoneStepAndEndsTheRun)
{
  int value = 0;
  QUndoStack stack;
  UndoMergeTracker tracker(&stack);

  EXPECT_FALSE(tracker.beginEdit(1));
  stack.push(new SetValueCommand(&value, 0, 1));
  tracker.recordEdit(1);

  const QUndoCommand* topBefore = stack.command(stack.index() - 1);
  const int indexBefore = stack.index();
  const int countBefore = stack.count();

  // Start a second step -- this undoes the first one, as in the merging
  // test above.
  EXPECT_TRUE(tracker.beginEdit(1));
  EXPECT_EQ(value, 0);

  // But this step fails to produce a replacement (e.g. the new value was
  // refused), so it must be abandoned rather than left undone.
  tracker.cancelEdit();

  EXPECT_EQ(value, 1);
  EXPECT_EQ(stack.index(), indexBefore);
  EXPECT_EQ(stack.count(), countBefore);
  EXPECT_EQ(stack.command(stack.index() - 1), topBefore);
  EXPECT_FALSE(stack.canRedo());

  // The run ended: the next edit on the same field starts fresh rather than
  // merging with the cancelled one.
  EXPECT_FALSE(tracker.beginEdit(1));
}
