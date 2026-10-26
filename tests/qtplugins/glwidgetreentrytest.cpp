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
