/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "editor.h"

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtGui/QMouseEvent>

#include <gtest/gtest.h>

#include <cmath>
#include <limits>
#include <vector>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Editor;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

QVariantList list(std::initializer_list<double> values)
{
  QVariantList result;
  for (double v : values)
    result << v;
  return result;
}

QVariantList ids(std::initializer_list<qlonglong> values)
{
  QVariantList result;
  for (qlonglong v : values)
    result << v;
  return result;
}

// Peroxide chain H0-O1-O2-H3 (bonds 0-1, 1-2, 2-3, all single).
class EditorCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildPeroxideChain();
    m_harness.attach(&m_editor);
    m_harness.registerCommands();
  }

  void expectRefused(const char* command, const QVariantMap& options,
                     const std::string& label)
  {
    const MoleculeSnapshot before = m_harness.snapshot();
    const CommandOutcome out = m_harness.run(command, options);
    EXPECT_TRUE(out.claimed) << label;
    EXPECT_EQ(out.status, CommandStatus::Failed)
      << label << ": " << describe(out);
    EXPECT_FALSE(out.message.isEmpty()) << label;
    EXPECT_TRUE(out.clean()) << label << ": " << describe(out);
    EXPECT_EQ(m_harness.snapshot(), before) << label;
  }

  Editor m_editor;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(EditorCommandTest, registersDocumentedCommands)
{
  const QStringList expected = { "addAtom", "addBond", "removeBond",
                                 "removeSelectedAtoms" };
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys().size(), expected.size());
  for (const QString& name : expected)
    EXPECT_TRUE(registered.contains(name)) << name.toStdString();
}

TEST_F(EditorCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "AddAtom", "selectAll" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::NotHandled) << name;
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

TEST_F(EditorCommandTest, addAtomBySymbolAndNumber)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  CommandOutcome out = m_harness.run(
    "addAtom", { { "element", "C" }, { "position", list({ 1, 2, 3 }) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 4);

  const MoleculeSnapshot after = m_harness.snapshot();
  ASSERT_EQ(after.atomicNumbers.size(), 5u);
  EXPECT_EQ(after.atomicNumbers[4], 6);
  EXPECT_EQ(after.positions[4], Vector3(1, 2, 3));
  EXPECT_EQ(after.bondPairs, before.bondPairs);
  EXPECT_EQ(after.undoIndex, before.undoIndex + 1);

  out = m_harness.run("addAtom", { { "element", qlonglong(8) },
                                   { "position", list({ -1, 0, 0.5 }) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 5);
  EXPECT_EQ(m_harness.snapshot().atomicNumbers[5], 8);
}

TEST_F(EditorCommandTest, addAtomWithBond)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  CommandOutcome out =
    m_harness.run("addAtom", { { "element", "H" },
                               { "position", list({ 0, 2, 0 }) },
                               { "bondTo", 0 },
                               { "bondOrder", 2 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 4);

  MoleculeSnapshot after = m_harness.snapshot();
  ASSERT_EQ(after.bondPairs.size(), before.bondPairs.size() + 1);
  EXPECT_EQ(after.bondPairs.back(), std::make_pair(Index(0), Index(4)));
  EXPECT_EQ(after.bondOrders.back(), 2);
  // One command, one undo entry.
  EXPECT_EQ(after.undoIndex, before.undoIndex + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after), QStringList());
}

TEST_F(EditorCommandTest, addAtomInvalidOptionsFail)
{
  const QVariantList pos = list({ 0, 0, 0 });
  const double nan = std::numeric_limits<double>::quiet_NaN();
  const double inf = std::numeric_limits<double>::infinity();
  const std::vector<QVariantMap> invalid = {
    {},
    { { "position", pos } },                                // no element
    { { "element", "C" } },                                 // no position
    { { "element", "Qq" }, { "position", pos } },           // bad symbol
    { { "element", qlonglong(0) }, { "position", pos } },   // Z = 0
    { { "element", qlonglong(-1) }, { "position", pos } },  // negative
    { { "element", qlonglong(999) }, { "position", pos } }, // too big
    { { "element", QVariantList() }, { "position", pos } }, // wrong type
    { { "element", "C" }, { "position", "0,0,0" } },        // not a list
    { { "element", "C" }, { "position", list({ 0, 0 }) } }, // 2 numbers
    { { "element", "C" }, { "position", list({ 0, 0, 0, 0 }) } },
    { { "element", "C" }, { "position", QVariantList{ 0, 0, "z" } } },
    { { "element", "C" }, { "position", list({ 0, nan, 0 }) } },
    { { "element", "C" }, { "position", list({ inf, 0, 0 }) } },
    { { "element", "C" }, { "position", list({ 0, -inf, 0 }) } },
    { { "element", "C" }, { "position", pos }, { "bondTo", 4 } }, // range
    { { "element", "C" }, { "position", pos }, { "bondTo", -1 } },
    { { "element", "C" }, { "position", pos }, { "bondTo", "0" } },
    { { "element", "C" }, { "position", pos }, { "bondTo", 0.5 } },
    { { "element", "C" },
      { "position", pos },
      { "bondTo", 0 },
      { "bondOrder", 0 } },
    { { "element", "C" },
      { "position", pos },
      { "bondTo", 0 },
      { "bondOrder", 4 } },
    { { "element", "C" },
      { "position", pos },
      { "bondTo", 0 },
      { "bondOrder", "single" } },
    { { "element", "C" },
      { "position", pos },
      { "bondTo", 0 },
      { "bondOrder", 1.5 } },
  };
  int n = 0;
  for (const QVariantMap& options : invalid)
    expectRefused("addAtom", options, "case " + std::to_string(n++));
}

TEST_F(EditorCommandTest, addBondAddsSingleBondByDefault)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  CommandOutcome out = m_harness.run("addBond", { { "atoms", ids({ 0, 3 }) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 3);

  MoleculeSnapshot after = m_harness.snapshot();
  ASSERT_EQ(after.bondPairs.size(), 4u);
  EXPECT_EQ(after.bondPairs[3], std::make_pair(Index(0), Index(3)));
  EXPECT_EQ(after.bondOrders[3], 1);
  EXPECT_EQ(after.undoIndex, before.undoIndex + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after), QStringList());

  // Reversed pair, explicit order, on a fresh molecule.
  m_harness.buildPeroxideChain();
  out =
    m_harness.run("addBond", { { "atoms", ids({ 3, 0 }) }, { "order", 3 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.snapshot().bondOrders.back(), 3);
}

TEST_F(EditorCommandTest, addBondInvalidOptionsFail)
{
  const std::vector<QVariantMap> invalid = {
    {},
    { { "atoms", ids({ 0 }) } },
    { { "atoms", ids({ 0, 1, 2 }) } },
    { { "atoms", "0,3" } },
    { { "atoms", QVariantList{ 0, "x" } } },
    { { "atoms", QVariantList{ 0, 1.5 } } },
    { { "atoms", ids({ 2, 2 }) } },                 // same atom
    { { "atoms", ids({ 0, 4 }) } },                 // out of range
    { { "atoms", ids({ -1, 2 }) } },                // negative
    { { "atoms", ids({ 1, 2 }) } },                 // already bonded
    { { "atoms", ids({ 2, 1 }) } },                 // already bonded, reversed
    { { "atoms", ids({ 1, 2 }) }, { "order", 3 } }, // never changes order
    { { "atoms", ids({ 0, 3 }) }, { "order", 0 } },
    { { "atoms", ids({ 0, 3 }) }, { "order", 4 } },
    { { "atoms", ids({ 0, 3 }) }, { "order", "double" } },
  };
  int n = 0;
  for (const QVariantMap& options : invalid)
    expectRefused("addBond", options, "case " + std::to_string(n++));
}

TEST_F(EditorCommandTest, removeBond)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out =
    m_harness.run("removeBond", { { "atoms", ids({ 2, 1 }) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  const MoleculeSnapshot after = m_harness.snapshot();
  ASSERT_EQ(after.bondPairs.size(), 2u);
  EXPECT_EQ(after.bondPairs[0], std::make_pair(Index(0), Index(1)));
  EXPECT_EQ(after.bondPairs[1], std::make_pair(Index(2), Index(3)));
  EXPECT_EQ(after.atomicNumbers, before.atomicNumbers);
  EXPECT_EQ(after.undoIndex, before.undoIndex + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after), QStringList());
}

TEST_F(EditorCommandTest, removeBondInvalidOptionsFail)
{
  const std::vector<QVariantMap> invalid = {
    {},
    { { "atoms", ids({ 0, 2 }) } }, // not bonded
    { { "atoms", ids({ 1, 1 }) } },
    { { "atoms", ids({ 0, 9 }) } },
    { { "atoms", ids({ -1, 0 }) } },
    { { "atoms", ids({ 0 }) } },
    { { "atoms", 5 } },
  };
  int n = 0;
  for (const QVariantMap& options : invalid)
    expectRefused("removeBond", options, "case " + std::to_string(n++));
}

TEST_F(EditorCommandTest, removeSelectedAtoms)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  m_harness.molecule()->setAtomSelected(1, true);
  m_harness.molecule()->setAtomSelected(3, true);
  const MoleculeSnapshot selected = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("removeSelectedAtoms");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("removed").toInt(), 2);

  // H0 and O2 remain; every bond touched a removed atom.
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.atomicNumbers, std::vector<unsigned char>({ 1, 8 }));
  EXPECT_TRUE(after.bondPairs.empty());
  EXPECT_EQ(after.undoIndex, selected.undoIndex + 1);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(selected, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(after), QStringList());
  (void)before;
}

TEST_F(EditorCommandTest, removeSelectedAtomsWithNothingSelected)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run("removeSelectedAtoms");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.result.value("removed").toInt(), 0);
  EXPECT_TRUE(out.result.contains("removed"));
  EXPECT_EQ(m_harness.snapshot(), before); // no undo entry either
}

TEST_F(EditorCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  const std::vector<std::pair<const char*, QVariantMap>> commands = {
    { "addAtom", { { "element", "C" }, { "position", list({ 0, 0, 0 }) } } },
    { "addBond", { { "atoms", ids({ 0, 1 }) } } },
    { "removeBond", { { "atoms", ids({ 0, 1 }) } } },
    { "removeSelectedAtoms", {} },
  };
  for (const auto& [name, options] : commands) {
    const CommandOutcome out = m_harness.run(name, options);
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.message, QString(NoMoleculeMessage)) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
}

TEST_F(EditorCommandTest, buildMoleculeFromEmpty)
{
  m_harness.buildEmpty();
  CommandOutcome out = m_harness.run(
    "addAtom", { { "element", "O" }, { "position", list({ 0, 0, 0 }) } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 0);
  out = m_harness.run("addAtom", { { "element", "H" },
                                   { "position", list({ 0.96, 0, 0 }) },
                                   { "bondTo", 0 } });
  ASSERT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("index").toInt(), 1);
  EXPECT_EQ(m_harness.snapshot().bondPairs.size(), 1u);
}

// Layer locks: like the mouse handlers, the commands refuse every edit while
// the active layer is locked.
namespace {
void setActiveLayerLocked(CommandTestHarness& harness, bool locked)
{
  auto info = harness.molecule()->layerInfo();
  info->locked[harness.molecule()->layer().activeLayer()] = locked;
}
} // namespace

TEST_F(EditorCommandTest, lockedActiveLayerRefusesEdits)
{
  m_harness.molecule()->setAtomSelected(1, true);
  setActiveLayerLocked(m_harness, true);
  const std::vector<std::pair<const char*, QVariantMap>> commands = {
    { "addAtom", { { "element", "C" }, { "position", list({ 0, 0, 0 }) } } },
    { "addAtom",
      { { "element", "C" },
        { "position", list({ 0, 0, 0 }) },
        { "bondTo", 0 } } },
    { "addBond", { { "atoms", ids({ 0, 3 }) } } },
    { "removeBond", { { "atoms", ids({ 1, 2 }) } } },
    { "removeSelectedAtoms", {} },
  };
  for (const auto& [name, options] : commands)
    expectRefused(name, options, name);
}

TEST_F(EditorCommandTest, lockedActiveLayerStillAllowsEmptyRemoval)
{
  setActiveLayerLocked(m_harness, true);
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run("removeSelectedAtoms");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toInt(), 0);
  EXPECT_EQ(m_harness.snapshot(), before);
}

TEST_F(EditorCommandTest, unlockingLetsTheSameCommandSucceed)
{
  setActiveLayerLocked(m_harness, true);
  const QVariantMap options = { { "atoms", ids({ 0, 3 }) } };
  expectRefused("addBond", options, "locked");
  setActiveLayerLocked(m_harness, false);
  const CommandOutcome out = m_harness.run("addBond", options);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.snapshot().bondPairs.size(), 4u);
}

// Atom 3 is put in a second, locked layer while layer 0 stays active and
// unlocked: edits that touch atom 3 must be refused, edits that do not must
// still work.
namespace {
void lockAtomInOtherLayer(CommandTestHarness& harness, Index atom)
{
  auto info = harness.molecule()->layerInfo();
  info->layer.addLayer();
  info->locked.push_back(true);
  info->visible.push_back(true);
  harness.molecule()->setLayer(atom, 1);
}
} // namespace

TEST_F(EditorCommandTest, lockedAtomRefusesEveryCommandTouchingIt)
{
  lockAtomInOtherLayer(m_harness, 3);
  const std::vector<std::pair<const char*, QVariantMap>> commands = {
    { "addAtom",
      { { "element", "C" },
        { "position", list({ 0, 0, 0 }) },
        { "bondTo", 3 } } },
    { "addBond", { { "atoms", ids({ 0, 3 }) } } },
    { "addBond", { { "atoms", ids({ 3, 0 }) } } },
    { "removeBond", { { "atoms", ids({ 2, 3 }) } } },
    { "removeBond", { { "atoms", ids({ 3, 2 }) } } },
  };
  for (const auto& [name, options] : commands)
    expectRefused(name, options, name);
}

TEST_F(EditorCommandTest, lockedAtomRefusesDeletingItOrItsNeighbours)
{
  lockAtomInOtherLayer(m_harness, 3);
  // The locked atom itself, and unlocked O2 which is bonded to it.
  for (Index selected : { Index(3), Index(2) }) {
    m_harness.molecule()->setAtomSelected(selected, true);
    expectRefused("removeSelectedAtoms", {},
                  "select " + std::to_string(selected));
    m_harness.molecule()->setAtomSelected(selected, false);
  }
  // A selection that includes one safe and one unsafe atom is not partially
  // deleted.
  m_harness.molecule()->setAtomSelected(0, true);
  m_harness.molecule()->setAtomSelected(2, true);
  expectRefused("removeSelectedAtoms", {}, "mixed selection");
}

TEST_F(EditorCommandTest, lockedAtomLeavesUntouchedAtomsEditable)
{
  lockAtomInOtherLayer(m_harness, 3);
  // H0 is two bonds away from the locked atom.
  m_harness.molecule()->setAtomSelected(0, true);
  CommandOutcome out = m_harness.run("removeSelectedAtoms");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(out.result.value("removed").toInt(), 1);
  // New atoms go into the active (unlocked) layer.
  out = m_harness.run(
    "addAtom", { { "element", "C" }, { "position", list({ 5, 0, 0 }) } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
}

namespace {

Index countHeavyAtoms(const Avogadro::QtGui::Molecule& mol)
{
  Index count = 0;
  for (Index i = 0; i < mol.atomCount(); ++i)
    if (mol.atomicNumber(i) != 1)
      ++count;
  return count;
}

// Drives the Draw tool with real mouse events against a CPU-only renderer.
//
// Scene plugins tag their atom spheres with the QtGui::Molecule address (see
// BallAndStick::process), and the renderer's hit test is pure CPU, so no GL
// context is needed. The scene is rebuilt after every event, as the app does
// on each molecule change: the editor always hits the previous frame.
class EditorDragScene
{
public:
  static constexpr int Width = 800;
  static constexpr int Height = 600;
  static constexpr float AtomRadius = 0.5f;

  EditorDragScene(Editor& editor, CommandTestHarness& harness)
    : m_editor(editor), m_harness(harness)
  {
    Avogadro::Rendering::Camera& camera = m_renderer.camera();
    camera.setViewport(Width, Height);
    camera.calculatePerspective(40.0f, 1.0f, 100.0f);
    camera.lookAt(Avogadro::Vector3f(0.0f, 0.0f, 10.0f),
                  Avogadro::Vector3f::Zero(), Avogadro::Vector3f::UnitY());
    m_editor.setGLRenderer(&m_renderer);
  }

  // Mimic a scene plugin: one sphere per atom, identified by the
  // QtGui::Molecule address, exactly as in ballandstick.cpp.
  void rebuildScene()
  {
    using namespace Avogadro::Rendering;
    m_renderer.scene().clear();
    auto* geometry = new GeometryNode;
    m_renderer.scene().rootNode().addChild(geometry);
    auto* spheres = new SphereGeometry;
    const Avogadro::QtGui::Molecule& mol = *m_harness.molecule();
    spheres->identifier().molecule = reinterpret_cast<const void*>(&mol);
    spheres->identifier().type = AtomType;
    geometry->addDrawable(spheres);
    for (Index i = 0; i < mol.atomCount(); ++i) {
      spheres->addSphere(mol.atomPosition3d(i).cast<float>(),
                         Avogadro::Vector3ub(100, 100, 100), AtomRadius, i);
    }
  }

  // Window coordinates (Qt: y down) of a world point.
  QPoint pixel(const Avogadro::Vector3f& world, float dx = 0.0f) const
  {
    const Avogadro::Vector3f p = m_renderer.camera().project(world);
    return QPoint(static_cast<int>(std::lround(p.x() + dx)),
                  static_cast<int>(std::lround(Height - p.y())));
  }

  // Index of the nearest atom under a pixel, or MaxIndex.
  Index atomAt(const QPoint& pos) const
  {
    const Avogadro::Rendering::Identifier id = m_renderer.hit(pos.x(), pos.y());
    return id.type == Avogadro::Rendering::AtomType ? id.index
                                                    : Avogadro::MaxIndex;
  }

  void press(const QPoint& pos) { send(QEvent::MouseButtonPress, pos); }
  void move(const QPoint& pos) { send(QEvent::MouseMove, pos); }
  void release(const QPoint& pos) { send(QEvent::MouseButtonRelease, pos); }

  Index heavyAtomCount() const
  {
    return countHeavyAtoms(*m_harness.molecule());
  }

private:
  void send(QEvent::Type type, const QPoint& pos)
  {
    const bool released = type == QEvent::MouseButtonRelease;
    QMouseEvent event(type, QPointF(pos), QPointF(pos), Qt::LeftButton,
                      released ? Qt::NoButton : Qt::LeftButton, Qt::NoModifier);
    if (type == QEvent::MouseButtonPress)
      m_editor.mousePressEvent(&event);
    else if (type == QEvent::MouseMove)
      m_editor.mouseMoveEvent(&event);
    else
      m_editor.mouseReleaseEvent(&event);
    rebuildScene();
  }

  Avogadro::Rendering::GLRenderer m_renderer;
  Editor& m_editor;
  CommandTestHarness& m_harness;
};

// Drag from atom 0 (origin) to atom 1, offset along x by 'x' and in depth by
// 'z', stopping first just outside atom 1 where the provisional atom, which
// follows the cursor at atom 0's depth, overlaps atom 1's centre.
void dragBondTo(Editor& editor, CommandTestHarness& harness, double x, double z,
                float approachPixels, bool provisionalCoversTarget)
{
  harness.buildEmpty();
  harness.molecule()->addAtom(6, Vector3(0.0, 0.0, 0.0));
  harness.molecule()->addAtom(6, Vector3(x, 0.0, z));

  EditorDragScene scene(editor, harness);
  scene.rebuildScene();

  const Avogadro::Vector3f a(0.0f, 0.0f, 0.0f);
  const Avogadro::Vector3f b(static_cast<float>(x), 0.0f,
                             static_cast<float>(z));
  const QPoint start = scene.pixel(a);
  const QPoint target = scene.pixel(b);
  const QPoint approach = scene.pixel(b, -approachPixels);
  ASSERT_EQ(scene.atomAt(start), Index(0));
  ASSERT_EQ(scene.atomAt(target), Index(1));
  // The approach point must be off atom 1, or no provisional atom is drawn.
  ASSERT_EQ(scene.atomAt(approach), Avogadro::MaxIndex);

  scene.press(start);
  scene.move(approach);
  // The provisional atom exists, and (behind case) covers atom 1's centre.
  ASSERT_EQ(harness.molecule()->atomCount(), Index(3));
  if (provisionalCoversTarget)
    ASSERT_EQ(scene.atomAt(target), Index(2));
  scene.move(target);
  scene.release(target);
}

} // namespace

// Atom 1 lies behind atom 0 as seen from the camera. The provisional atom
// follows the cursor at atom 0's depth, so it is the nearest hit over atom 1;
// the editor must not mistake it for the atom to bond to.
TEST_F(EditorCommandTest, dragBondsToAtomBehindClickedAtom)
{
  dragBondTo(m_editor, m_harness, 2.0, -3.0, 38.0f, true);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  const auto* mol = m_harness.molecule();
  ASSERT_TRUE(mol->bond(0, 1).isValid());
  // The provisional atom is gone; hydrogens may have been added.
  EXPECT_EQ(countHeavyAtoms(*mol), Index(2));
  EXPECT_EQ(mol->bond(0, 1).order(), 1);
}

TEST_F(EditorCommandTest, dragBondsToAtomInFrontOfClickedAtom)
{
  dragBondTo(m_editor, m_harness, 2.0, 3.0, 70.0f, false);
  ASSERT_FALSE(::testing::Test::HasFatalFailure());
  EXPECT_TRUE(m_harness.molecule()->bond(0, 1).isValid());
  EXPECT_EQ(countHeavyAtoms(*m_harness.molecule()), Index(2));
}

// Dragging back over the clicked atom removes the provisional atom.
TEST_F(EditorCommandTest, dragBackOverClickedAtomRemovesNewAtom)
{
  m_harness.buildEmpty();
  m_harness.molecule()->addAtom(6, Vector3(0.0, 0.0, 0.0));
  EditorDragScene scene(m_editor, m_harness);
  scene.rebuildScene();

  const QPoint start = scene.pixel(Avogadro::Vector3f(0.0f, 0.0f, 0.0f));
  ASSERT_EQ(scene.atomAt(start), Index(0));
  scene.press(start);
  scene.move(start + QPoint(200, 0));
  EXPECT_EQ(scene.heavyAtomCount(), Index(2));
  scene.move(start + QPoint(100, 0));
  EXPECT_EQ(scene.heavyAtomCount(), Index(2));
  // Back over atom 0, where the provisional atom is also under the cursor.
  scene.move(start);
  EXPECT_EQ(scene.heavyAtomCount(), Index(1));
  scene.release(start);
  EXPECT_EQ(scene.heavyAtomCount(), Index(1));
  // Hydrogens aside, atom 0 is bonded to nothing.
  for (Index i = 1; i < m_harness.molecule()->atomCount(); ++i)
    EXPECT_EQ(m_harness.molecule()->atomicNumber(i), 1);
}
