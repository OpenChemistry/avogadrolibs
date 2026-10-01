/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "focus.h"

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>

#include <gtest/gtest.h>

using Avogadro::Vector3f;
using Avogadro::QtPlugins::Focus;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::recordKnownDeviation;
using Avogadro::QtPluginsTests::recordUndecided;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::Scene;

// Focus changes only the camera. Camera and Scene are plain objects (no GL
// context), so the harness hands the plugin its own; no GLWidget is needed.
// The camera works in float, hence the 1e-5 tolerance.
namespace {

constexpr float CamTol = 1e-5f;

::testing::AssertionResult near(const Vector3f& actual,
                                const Vector3f& expected)
{
  if ((actual - expected).cwiseAbs().maxCoeff() <= CamTol)
    return ::testing::AssertionSuccess();
  return ::testing::AssertionFailure()
         << "got (" << actual.x() << ", " << actual.y() << ", " << actual.z()
         << "), expected (" << expected.x() << ", " << expected.y() << ", "
         << expected.z() << ")";
}

class FocusCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildPeroxideChain();
    m_harness.attach(&m_focus);
    m_focus.setCamera(&m_camera);
    m_focus.setScene(&m_scene);
    m_harness.registerCommands();
  }

  // Where the camera is, in model coordinates.
  Vector3f eye() const { return m_camera.modelView().inverse().translation(); }

  Camera m_camera;
  Scene m_scene;
  Focus m_focus;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(FocusCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys(), QStringList({ "focusSelection", "unfocus" }));
}

// Selecting O1 (0,0,0) and O2 (1.5,0,0): centroid (0.75, 0, 0), radius 0.75
// (both atoms are 0.75 from it), so the target distance is 0.75 + 10 = 10.75.
// Starting from an identity camera at the origin, the eye moves along the
// line of sight until it is 10.75 from the centroid on the far side from it:
// eye = 0 + (0.75, 0, 0) * (1 - 10.75 / 0.75) = (-10, 0, 0).
TEST_F(FocusCommandTest, focusSelectionAimsAtTheSelectionCentroid)
{
  m_harness.molecule()->setAtomSelected(1, true);
  m_harness.molecule()->setAtomSelected(2, true);
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("focusSelection");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  EXPECT_TRUE(near(m_camera.focus(), Vector3f(0.75f, 0.0f, 0.0f)));
  EXPECT_TRUE(near(eye(), Vector3f(-10.0f, 0.0f, 0.0f)));
  EXPECT_NEAR((eye() - m_camera.focus()).norm(), 10.75f, CamTol);
  // The molecule, selection and undo stack are untouched.
  EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());
}

// unfocus resets the view the way GLRenderer::resetCamera() does: focus on
// the scene centre, eye 1.5 scene radii back along +z. Those are rendering
// quantities (an empty scene here), so they are taken from the scene rather
// than derived from the molecule.
TEST_F(FocusCommandTest, unfocusResetsToTheScene)
{
  m_harness.molecule()->setAtomSelected(1, true);
  ASSERT_EQ(m_harness.run("focusSelection").status, CommandStatus::Finished);
  const MoleculeSnapshot before = m_harness.snapshot();

  const CommandOutcome out = m_harness.run("unfocus");
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);

  const Vector3f center = m_scene.center();
  EXPECT_TRUE(near(m_camera.focus(), center));
  EXPECT_TRUE(
    near(eye(), center + 1.5f * m_scene.radius() * Vector3f::UnitZ()));
  EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());
}

TEST_F(FocusCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "FocusSelection", "resetView" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 1): no molecule -> true + commandFailed("No molecule").
TEST_F(FocusCommandTest, knownDeviationNoMoleculeIsNotClaimed)
{
  recordKnownDeviation("with no molecule every command returns false");

  m_harness.setPluginMolecule(nullptr);
  for (const char* name : { "focusSelection", "unfocus" }) {
    const CommandOutcome out = m_harness.run(name);
    // When this fails, expect claimed, Failed, NoMoleculeMessage.
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
}

// Not settled by the decisions: with nothing selected, or no camera (no
// view), focusSelection claims the command and silently does nothing.
TEST_F(FocusCommandTest, undecidedFocusWithoutSelectionOrCameraIsSilentNoOp)
{
  recordUndecided("focusSelection with an empty selection or no camera "
                  "returns true and does nothing");

  const Eigen::Affine3f view = m_camera.modelView();
  CommandOutcome out = m_harness.run("focusSelection");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_TRUE(view.isApprox(m_camera.modelView()));

  m_harness.molecule()->setAtomSelected(1, true);
  m_focus.setCamera(nullptr);
  out = m_harness.run("focusSelection");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(view.isApprox(m_camera.modelView()));
}
