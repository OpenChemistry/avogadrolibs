/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Tool mouse and key handling, driven through a never-shown GLWidget by
// ToolInteractionHarness: the path a user's click takes, which the command
// tests (handleCommand()) do not exercise. Atoms are clicked by index, so
// nothing here depends on pixel positions.

#include "plugintestutils.h"
#include "toolinteractionharness.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtGui/QUndoStack>
#include <QtWidgets/QAbstractButton>
#include <QtWidgets/QDialogButtonBox>

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>

using namespace Avogadro;
using QtPluginsTests::MoleculeSnapshot;
using QtPluginsTests::ToolInteractionHarness;

namespace {

class ToolInteractionTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    auto ballStick = QtPluginsTests::createScenePlugin("BallStick");
    ASSERT_NE(ballStick, nullptr) << "no BallStick scene plugin";
    h.addScenePlugin(ballStick.release());
    h.buildMethanol();
  }

  /** Make the plugin @p id the active tool. @return It, owned by the widget. */
  QtGui::ToolPlugin* activate(const char* id)
  {
    auto tool = QtPluginsTests::createTool(id);
    EXPECT_NE(tool, nullptr) << "no " << id << " tool";
    QtGui::ToolPlugin* raw = tool.release();
    h.setActiveTool(raw);
    return raw;
  }

  /** As in the application: Navigator gets whatever the active tool leaves. */
  void useNavigatorAsDefault()
  {
    auto navigator = QtPluginsTests::createTool("Navigator");
    ASSERT_NE(navigator, nullptr);
    h.setDefaultTool(navigator.release());
  }

  bool hasBond(Index a, Index b) const
  {
    const auto& pairs = h.molecule()->bondPairs();
    return std::any_of(pairs.begin(), pairs.end(), [a, b](const auto& p) {
      return (p.first == a && p.second == b) || (p.first == b && p.second == a);
    });
  }

  /** Undo everything the test did; the molecule must be back at @p start. */
  void expectUndoneTo(const MoleculeSnapshot& start)
  {
    QUndoStack& stack = h.molecule()->undoMolecule()->undoStack();
    while (stack.canUndo())
      EXPECT_TRUE(h.commands().undo().isEmpty());
    EXPECT_TRUE(h.commands().snapshot().differences(start, false).isEmpty())
      << h.commands()
           .snapshot()
           .differences(start, false)
           .join(QStringLiteral("; "))
           .toStdString();
  }

  void expectClean() const
  {
    const QStringList v = h.commands().checkInvariants();
    EXPECT_TRUE(v.isEmpty()) << v.join(QStringLiteral("; ")).toStdString();
  }

  ToolInteractionHarness h;
};

// The harness itself: picking by index must land on that atom, or every test
// below is clicking the wrong thing.
TEST_F(ToolInteractionTest, pointOnAtomPicksThatAtom)
{
  // Atoms 3 and 4 share x and y and overlap in the reset (down -z) view.
  for (Index atom : { 0, 1, 2, 5 }) {
    const Rendering::Identifier hit = h.hitAt(h.pointOnAtom(atom));
    EXPECT_EQ(hit.type, Rendering::AtomType) << "atom " << atom;
    EXPECT_EQ(hit.index, atom);
  }
  // The nearer of the two (larger z) wins.
  EXPECT_EQ(h.hitAt(h.pointOnAtom(4)).index, Index(3));

  const Rendering::Identifier bond = h.hitAt(h.pointOnBond(0));
  EXPECT_EQ(bond.type, Rendering::BondType);
  EXPECT_EQ(bond.index, Index(0));

  EXPECT_FALSE(h.hitAt(h.emptyPoint()).isValid());
}

TEST_F(ToolInteractionTest, editorClickInEmptySpaceAddsCarbon)
{
  activate("Editor");
  const MoleculeSnapshot before = h.commands().snapshot();
  const Index n = h.molecule()->atomCount();

  h.click(h.emptyPoint());

  ASSERT_GT(h.molecule()->atomCount(), n);
  EXPECT_EQ(h.molecule()->atomicNumber(n), Core::Carbon);
  // Hydrogen adjustment is on by default: methane, bonded to nothing else.
  EXPECT_EQ(h.molecule()->atomCount(), n + 5);
  for (Index i = n + 1; i < n + 5; ++i) {
    EXPECT_EQ(h.molecule()->atomicNumber(i), Core::Hydrogen);
    EXPECT_TRUE(hasBond(n, i)) << "H " << i;
  }
  // The new atom is where the click was.
  const Rendering::Identifier hit = h.hitAt(h.emptyPoint());
  EXPECT_EQ(hit.type, Rendering::AtomType);
  EXPECT_EQ(hit.index, n);
  expectClean();

  // One user action, one undo step.
  EXPECT_EQ(h.molecule()->undoMolecule()->undoStack().count(), 1);
  expectUndoneTo(before);
}

TEST_F(ToolInteractionTest, editorTypedSymbolSetsElement)
{
  activate("Editor");
  const Index n = h.molecule()->atomCount();

  h.keyPress(Qt::Key_N, Qt::NoModifier, QStringLiteral("n"));
  h.click(h.emptyPoint());

  ASSERT_GT(h.molecule()->atomCount(), n);
  EXPECT_EQ(h.molecule()->atomicNumber(n), Core::Nitrogen);
  // Ammonia.
  EXPECT_EQ(h.molecule()->atomCount(), n + 4);
  expectClean();
}

TEST_F(ToolInteractionTest, editorDragFromAtomAddsBondedAtom)
{
  // While a bond is dragged the Editor draws its length as a text label,
  // whose constructor needs an OpenGL context.
  if (!QtPluginsTests::haveGLContext())
    GTEST_SKIP() << "no OpenGL context for the Editor's text label";
  activate("Editor");
  const MoleculeSnapshot before = h.commands().snapshot();
  const Index n = h.molecule()->atomCount();

  // From the oxygen (atom 1) out to an empty corner.
  h.drag(h.pointOnAtom(1), h.emptyPoint());

  // The new carbon takes the place of the hydroxyl hydrogen (an oxygen keeps
  // two bonds) and is itself filled out with hydrogens: methanol becomes
  // dimethyl ether, CH3-O-CH3. Atom indices are not stable across the
  // hydrogen removal, so look at the structure, not at a particular index.
  EXPECT_EQ(h.molecule()->atomCount(), n + 3);
  EXPECT_EQ(h.molecule()->atomicNumber(1), Core::Oxygen);
  Index carbons = 0, hydrogens = 0, oxygenCarbons = 0;
  for (Index i = 0; i < h.molecule()->atomCount(); ++i) {
    const bool carbon = h.molecule()->atomicNumber(i) == Core::Carbon;
    carbons += carbon;
    hydrogens += h.molecule()->atomicNumber(i) == Core::Hydrogen;
    oxygenCarbons += carbon && hasBond(1, i);
  }
  EXPECT_EQ(carbons, 2);
  EXPECT_EQ(hydrogens, 6);
  EXPECT_EQ(oxygenCarbons, 2);
  expectClean();
  EXPECT_EQ(h.molecule()->undoMolecule()->undoStack().count(), 1);
  expectUndoneTo(before);
}

TEST_F(ToolInteractionTest, editorClickOnBondCyclesOrder)
{
  activate("Editor");
  const MoleculeSnapshot before = h.commands().snapshot();
  ASSERT_EQ(h.molecule()->bondOrder(0), 1);

  h.click(h.pointOnBond(0)); // C-O
  EXPECT_EQ(h.molecule()->bondOrder(0), 2);
  expectClean();

  expectUndoneTo(before);
}

TEST_F(ToolInteractionTest, editorRightClickDeletesAtom)
{
  activate("Editor");
  const MoleculeSnapshot before = h.commands().snapshot();
  const Index n = h.molecule()->atomCount();

  h.click(h.pointOnAtom(5), Qt::RightButton); // the hydroxyl H

  EXPECT_LT(h.molecule()->atomCount(), n);
  expectClean();
  expectUndoneTo(before);
}

TEST_F(ToolInteractionTest, navigationModifierBypassesEditor)
{
  activate("Editor");
  useNavigatorAsDefault();
  const MoleculeSnapshot before = h.commands().snapshot();
  const Eigen::Affine3f view = h.camera().modelView();

  // Alt (the default navigation modifier) + drag: rotate, never draw.
  h.drag(h.emptyPoint(), QPoint(200, 120), Qt::LeftButton, Qt::AltModifier);

  EXPECT_TRUE(h.commands().snapshot().differences(before).isEmpty());
  EXPECT_FALSE(h.camera().modelView().isApprox(view));
}

TEST_F(ToolInteractionTest, navigatorChangesOnlyTheCamera)
{
  activate("Navigator");
  const MoleculeSnapshot before = h.commands().snapshot();

  Eigen::Affine3f view = h.camera().modelView();
  h.drag(QPoint(200, 200), QPoint(260, 230)); // rotate
  EXPECT_FALSE(h.camera().modelView().isApprox(view));

  view = h.camera().modelView();
  const float distance = h.camera().distance(Vector3f::Zero());
  h.wheel(QPoint(200, 200), 120); // zoom
  EXPECT_NE(h.camera().distance(Vector3f::Zero()), distance);

  view = h.camera().modelView();
  h.drag(QPoint(200, 200), QPoint(230, 200), Qt::RightButton); // pan
  EXPECT_FALSE(h.camera().modelView().isApprox(view));

  EXPECT_TRUE(h.commands().snapshot().differences(before).isEmpty())
    << h.commands().snapshot().differences(before).join("; ").toStdString();
}

TEST_F(ToolInteractionTest, selectionClickSelectsOneAtom)
{
  activate("Selection");
  h.click(h.pointOnAtom(1));
  EXPECT_EQ(h.commands().snapshot().selectedIndices(), std::vector<Index>{ 1 });

  // A plain click elsewhere replaces the selection.
  h.click(h.pointOnAtom(0));
  EXPECT_EQ(h.commands().snapshot().selectedIndices(), std::vector<Index>{ 0 });
  expectClean();
}

TEST_F(ToolInteractionTest, selectionBoxSelectsEverythingInside)
{
  activate("Selection");
  const int edge = ToolInteractionHarness::ViewportSize - 5;
  h.drag(h.emptyPoint(), QPoint(edge, edge));

  const std::vector<Index> all{ 0, 1, 2, 3, 4, 5 };
  EXPECT_EQ(h.commands().snapshot().selectedIndices(), all);
  expectClean();
}

TEST_F(ToolInteractionTest, manipulatorDragMovesOnlyThatAtom)
{
  activate("Manipulator");
  const MoleculeSnapshot before = h.commands().snapshot();
  const QPoint from = h.pointOnAtom(1);
  const QPoint to = from + QPoint(30, -20);
  const float depth =
    h.camera().project(h.molecule()->atomPosition3d(1).cast<float>()).z();

  h.drag(from, to);

  // The atom follows the cursor in the view plane, at the same depth.
  const QPoint landed = h.pointOnAtom(1);
  EXPECT_LE((landed - to).manhattanLength(), 2)
    << "landed at " << landed.x() << "," << landed.y();
  EXPECT_NEAR(
    h.camera().project(h.molecule()->atomPosition3d(1).cast<float>()).z(),
    depth, 1e-4);

  const MoleculeSnapshot after = h.commands().snapshot();
  for (Index i = 0; i < after.positions.size(); ++i) {
    if (i != 1)
      EXPECT_EQ(after.positions[i], before.positions[i]) << "atom " << i;
  }
  expectClean();
  expectUndoneTo(before);
}

} // namespace

// Regression: the Manipulator dereferenced its molecule in mouseMoveEvent()
// (and in the tool panel's Apply handler) without checking for null, which is
// what a tool holds before a molecule is set and after one is closed.
TEST_F(ToolInteractionTest, manipulatorWithoutMoleculeDoesNothing)
{
  QtGui::ToolPlugin* tool = activate("Manipulator");
  tool->setEditMolecule(nullptr);
  tool->setMolecule(nullptr);

  const QPoint from = h.pointOnAtom(1);
  const QPoint to = from + QPoint(30, -20);
  h.click(from);
  h.drag(from, to);
  h.drag(h.emptyPoint(), to);
  h.drag(from, to, Qt::RightButton, Qt::ShiftModifier);
  h.move(to);
  h.wheel(to, 120);
  for (int key : { int(Qt::Key_Left), int(Qt::Key_Up), int(Qt::Key_Escape) }) {
    h.keyPress(key);
    h.keyRelease(key);
  }

  // The tool panel's Apply and Reset buttons.
  auto* buttons = tool->toolWidget()->findChild<QDialogButtonBox*>();
  ASSERT_NE(buttons, nullptr);
  for (QAbstractButton* button : buttons->buttons())
    button->click();

  // Nothing else in the molecule changed hands.
  expectClean();
}
