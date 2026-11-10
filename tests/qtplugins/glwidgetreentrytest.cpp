/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Regression tests: a scene plugin that spins a nested event loop while it is
// building the scene (the OpenBabel charge calculation does) can cause
// GLWidget::updateScene() to be re-entered. The nested call used to clear the
// scene nodes the outer pass was still filling, a use-after-free. The nested
// request must now be deferred until the running pass has finished.

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/scene.h>

#include <gtest/gtest.h>

using Avogadro::QtOpenGL::GLWidget;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;

namespace {

class ReentrantPlugin : public Avogadro::QtGui::ScenePlugin
{
public:
  enum class Mode
  {
    UpdateScene,
    ClearScene
  };

  QString name() const override { return "Reentrant"; }
  QString description() const override { return "Test plugin"; }
  // The layer manager needs a registered active molecule; skip it.
  bool isEnabled() const override { return true; }

  void process(const Avogadro::QtGui::Molecule&, GroupNode& node) override
  {
    ++calls;
    ++depth;
    if (depth > maxDepth)
      maxDepth = depth;
    node.addChild(new GeometryNode);
    if (calls == 1) {
      // what a nested event loop delivering a molecule change would do
      if (mode == Mode::UpdateScene)
        widget->updateScene();
      else
        widget->clearScene();
      callsAfterNested = calls;
    }
    // keep using the node after the nested request
    node.addChild(new GeometryNode);
    --depth;
  }

  GLWidget* widget = nullptr;
  Mode mode = Mode::UpdateScene;
  int calls = 0;
  int callsAfterNested = 0;
  int depth = 0;
  int maxDepth = 0;
};

// Root -> molecule node -> one engine node with two geometry children.
void expectFinalStructure(GLWidget& widget)
{
  auto& root = widget.renderer().scene().rootNode();
  ASSERT_EQ(root.children().size(), 1u);
  auto* molNode = dynamic_cast<GroupNode*>(root.children().front().node);
  ASSERT_NE(molNode, nullptr);
  ASSERT_EQ(molNode->children().size(), 1u);
  auto* engine = dynamic_cast<GroupNode*>(molNode->children().front().node);
  ASSERT_NE(engine, nullptr);
  EXPECT_EQ(engine->children().size(), 2u);
}

void runCase(ReentrantPlugin::Mode mode)
{
  GLWidget widget;
  auto* molecule = new Avogadro::QtGui::Molecule(&widget);
  widget.setMolecule(molecule);

  auto* plugin = new ReentrantPlugin;
  plugin->widget = &widget;
  plugin->mode = mode;
  widget.sceneModel().addItem(plugin);

  widget.updateScene();

  // The nested request did not run inside the first pass (it saw no second
  // process() call), but the scene was rebuilt once afterwards.
  EXPECT_EQ(plugin->callsAfterNested, 1);
  EXPECT_EQ(plugin->calls, 2);
  EXPECT_EQ(plugin->maxDepth, 1);
  expectFinalStructure(widget);

  // And the widget is usable afterwards.
  plugin->mode = ReentrantPlugin::Mode::ClearScene;
  plugin->calls = 5; // no further nested request
  widget.updateScene();
  EXPECT_EQ(plugin->calls, 6);
  expectFinalStructure(widget);
}

} // namespace

TEST(GLWidgetReentryTest, nestedUpdateSceneIsDeferred)
{
  runCase(ReentrantPlugin::Mode::UpdateScene);
}

TEST(GLWidgetReentryTest, clearSceneDuringBuildIsDeferred)
{
  runCase(ReentrantPlugin::Mode::ClearScene);
}

namespace {

using Avogadro::QtGui::Molecule;

class CoordPlugin : public Avogadro::QtGui::ScenePlugin
{
public:
  QString name() const override { return "Coord"; }
  QString description() const override { return "Test plugin"; }
  bool isEnabled() const override { return true; }
  void process(const Molecule&, GroupNode& node) override
  {
    ++processCalls;
    node.addChild(new GeometryNode);
  }
  bool updateCoordinates(const Molecule&, GroupNode&) override
  {
    ++coordCalls;
    return inPlace;
  }
  int processCalls = 0;
  int coordCalls = 0;
  // What updateCoordinates() returns; false asks the widget to rebuild.
  bool inPlace = true;
};

} // namespace

TEST(GLWidgetCoalesceTest, changesAreCoalescedUntilApplied)
{
  GLWidget widget;
  auto* molecule = new Avogadro::QtGui::Molecule(&widget);
  widget.setMolecule(molecule);
  auto* plugin = new CoordPlugin;
  widget.sceneModel().addItem(plugin);

  molecule->emitChanged(Avogadro::QtGui::Molecule::Atoms);
  molecule->emitChanged(Avogadro::QtGui::Molecule::Atoms |
                        Avogadro::QtGui::Molecule::Added);
  molecule->emitChanged(Avogadro::QtGui::Molecule::Bonds);
  EXPECT_EQ(plugin->processCalls, 0);

  widget.applyPendingSceneChanges();
  EXPECT_EQ(plugin->processCalls, 1);

  // Nothing pending now.
  widget.applyPendingSceneChanges();
  EXPECT_EQ(plugin->processCalls, 1);
}

TEST(GLWidgetCoalesceTest, updateSceneIsImmediateAndClearsPending)
{
  GLWidget widget;
  auto* molecule = new Avogadro::QtGui::Molecule(&widget);
  widget.setMolecule(molecule);
  auto* plugin = new CoordPlugin;
  widget.sceneModel().addItem(plugin);

  molecule->emitChanged(Avogadro::QtGui::Molecule::Atoms);
  EXPECT_EQ(plugin->processCalls, 0);
  widget.updateScene();
  EXPECT_EQ(plugin->processCalls, 1);

  widget.applyPendingSceneChanges();
  EXPECT_EQ(plugin->processCalls, 1);
}

// Positions-only dispatch: a coordinate change keeps the scene tree and calls
// ScenePlugin::updateCoordinates() instead of process().
namespace {

struct CoordFixture
{
  CoordFixture()
  {
    molecule = new Molecule(&widget);
    widget.setMolecule(molecule);
    plugin = new CoordPlugin;
    widget.sceneModel().addItem(plugin);
    widget.updateScene();
    plugin->processCalls = 0;
  }
  // Emit `changes` and apply; true if the positions-only path ran.
  bool coordsPath(unsigned int changes)
  {
    plugin->processCalls = plugin->coordCalls = 0;
    molecule->emitChanged(changes);
    widget.applyPendingSceneChanges();
    EXPECT_EQ(plugin->processCalls + plugin->coordCalls, 1);
    return plugin->coordCalls == 1 && plugin->processCalls == 0;
  }
  GLWidget widget;
  Molecule* molecule = nullptr;
  CoordPlugin* plugin = nullptr;
};

} // namespace

TEST(GLWidgetCoordsTest, movedAtomsUpdateCoordinates)
{
  CoordFixture f;
  EXPECT_TRUE(f.coordsPath(Molecule::Atoms | Molecule::Moved));
  EXPECT_TRUE(f.coordsPath(Molecule::Moved));
  EXPECT_TRUE(
    f.coordsPath(Molecule::Atoms | Molecule::Moved | Molecule::Conformer));
  EXPECT_TRUE(f.coordsPath(Molecule::Conformer));
}

TEST(GLWidgetCoordsTest, coalescedMovesStayOnCoordsPath)
{
  CoordFixture f;
  f.plugin->coordCalls = 0;
  f.molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
  f.molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->coordCalls, 1);
  EXPECT_EQ(f.plugin->processCalls, 0);
}

TEST(GLWidgetCoordsTest, otherChangesRebuildFully)
{
  CoordFixture f;
  EXPECT_FALSE(f.coordsPath(Molecule::Atoms | Molecule::Added));
  EXPECT_FALSE(f.coordsPath(Molecule::Bonds | Molecule::Modified));
  EXPECT_FALSE(
    f.coordsPath(Molecule::Atoms | Molecule::Moved | Molecule::Bonds));
  EXPECT_FALSE(f.coordsPath(Molecule::Layers));
  EXPECT_FALSE(f.coordsPath(Molecule::Selection));
  EXPECT_FALSE(f.coordsPath(Molecule::Atoms));
  // A move merged with an unrelated change in the same frame.
  f.plugin->processCalls = f.plugin->coordCalls = 0;
  f.molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
  f.molecule->emitChanged(Molecule::Atoms | Molecule::Removed);
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->processCalls, 1);
  EXPECT_EQ(f.plugin->coordCalls, 0);
}

TEST(GLWidgetCoordsTest, noPriorBuildIsFull)
{
  GLWidget widget;
  auto* molecule = new Molecule(&widget);
  widget.setMolecule(molecule);
  auto* plugin = new CoordPlugin;
  widget.sceneModel().addItem(plugin);
  molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
  widget.applyPendingSceneChanges();
  EXPECT_EQ(plugin->processCalls, 1);
  EXPECT_EQ(plugin->coordCalls, 0);
}

TEST(GLWidgetCoordsTest, differentMoleculeIsFull)
{
  CoordFixture f;
  auto* other = new Molecule(&f.widget);
  f.widget.setMolecule(other);
  f.plugin->processCalls = f.plugin->coordCalls = 0;
  other->emitChanged(Molecule::Atoms | Molecule::Moved);
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->processCalls, 1);
  EXPECT_EQ(f.plugin->coordCalls, 0);
}

TEST(GLWidgetCoordsTest, pluginChangesAreFull)
{
  CoordFixture f;
  // A plugin state change.
  emit f.widget.sceneModel().pluginStateChanged(f.plugin);
  f.molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
  f.plugin->processCalls = 0;
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->processCalls, 1);
  EXPECT_EQ(f.plugin->coordCalls, 0);
  // Coordinates work again once the rebuild has recorded a tree.
  EXPECT_TRUE(f.coordsPath(Molecule::Moved));

  // A different set of active plugins, with no signal at all.
  auto* second = new CoordPlugin;
  f.widget.sceneModel().addItem(second);
  f.plugin->processCalls = f.plugin->coordCalls = 0;
  f.molecule->emitChanged(Molecule::Moved);
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->processCalls, 1);
  EXPECT_EQ(second->processCalls, 1);
  EXPECT_EQ(f.plugin->coordCalls + second->coordCalls, 0);
}

TEST(GLWidgetCoordsTest, clearedSceneIsFull)
{
  CoordFixture f;
  f.widget.clearScene();
  f.plugin->processCalls = f.plugin->coordCalls = 0;
  f.molecule->emitChanged(Molecule::Moved);
  f.widget.applyPendingSceneChanges();
  EXPECT_EQ(f.plugin->processCalls, 1);
  EXPECT_EQ(f.plugin->coordCalls, 0);
}

TEST(GLWidgetCoordsTest, fallbackKeepsNodeAndDoesNotAccumulate)
{
  CoordFixture f;
  f.plugin->inPlace = false;
  auto& root = f.widget.renderer().scene().rootNode();
  auto* molNode = dynamic_cast<GroupNode*>(root.children().front().node);
  ASSERT_NE(molNode, nullptr);
  auto* engine = dynamic_cast<GroupNode*>(molNode->children().front().node);
  ASSERT_NE(engine, nullptr);
  EXPECT_EQ(engine->children().size(), 1u);
  for (int i = 0; i < 3; ++i) {
    f.plugin->processCalls = f.plugin->coordCalls = 0;
    f.molecule->emitChanged(Molecule::Atoms | Molecule::Moved);
    f.widget.applyPendingSceneChanges();
    EXPECT_EQ(f.plugin->coordCalls, 1);
    EXPECT_EQ(f.plugin->processCalls, 1); // the widget's fallback
    ASSERT_EQ(molNode->children().size(), 1u);
    EXPECT_EQ(molNode->children().front().node, engine);
    EXPECT_EQ(engine->children().size(), 1u);
  }
}

TEST(GLWidgetCoordsTest, inPlaceUpdateLeavesNodeAlone)
{
  CoordFixture f;
  auto& root = f.widget.renderer().scene().rootNode();
  auto* molNode = dynamic_cast<GroupNode*>(root.children().front().node);
  ASSERT_NE(molNode, nullptr);
  auto* engine = dynamic_cast<GroupNode*>(molNode->children().front().node);
  ASSERT_NE(engine, nullptr);
  auto* child = engine->children().front().node;
  EXPECT_TRUE(f.coordsPath(Molecule::Atoms | Molecule::Moved));
  EXPECT_EQ(f.plugin->processCalls, 0);
  ASSERT_EQ(engine->children().size(), 1u);
  EXPECT_EQ(engine->children().front().node, child);
}
