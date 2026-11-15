/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "autoopt.h"

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/qtgui/molecule.h>

#include <atomic>

#include <QComboBox>
#include <QPushButton>

#include <gtest/gtest.h>

using Avogadro::Vector3;
using Avogadro::QtGui::Molecule;
using Avogadro::QtPlugins::AutoOpt;

namespace {
std::atomic<int> liveCalculators{ 0 };

class TrackedCalculator : public Avogadro::Calc::LennardJones
{
public:
  TrackedCalculator() { ++liveCalculators; }
  ~TrackedCalculator() override { --liveCalculators; }
  TrackedCalculator* newInstance() const override
  {
    return new TrackedCalculator;
  }
  std::string identifier() const override { return "AutoOptLifetimeTest"; }
};

class AutoOptCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    molecule.addAtom(6).setPosition3d(Vector3::Zero());
    tool.setMolecule(&molecule);
  }

  Molecule molecule;
  AutoOpt tool;
};
} // namespace

TEST_F(AutoOptCommandTest, buttonTracksRunningState)
{
  auto* button = tool.toolWidget()->findChild<QPushButton*>("startStopButton");
  ASSERT_NE(button, nullptr);
  EXPECT_EQ(button->text(), "Start");
  ASSERT_TRUE(tool.handleCommand("startAutoOptimize", { { "method", "UFF" } }));
  EXPECT_EQ(button->text(), "Stop");
  EXPECT_TRUE(tool.handleCommand("stopAutoOptimize", {}));
  EXPECT_EQ(button->text(), "Start");
}

TEST_F(AutoOptCommandTest, widgetCreatedWhileRunningShowsStop)
{
  ASSERT_TRUE(tool.handleCommand("startAutoOptimize", { { "method", "UFF" } }));
  auto* button = tool.toolWidget()->findChild<QPushButton*>("startStopButton");
  ASSERT_NE(button, nullptr);
  EXPECT_EQ(button->text(), "Stop");
  tool.stop();
  EXPECT_EQ(button->text(), "Start");
}

TEST_F(AutoOptCommandTest, commandMethodIsNotOverwrittenByWidget)
{
  auto* methods = tool.toolWidget()->findChild<QComboBox*>("methodComboBox");
  ASSERT_NE(methods, nullptr);
  // An empty menu selection must not replace the valid command method.
  methods->setCurrentIndex(-1);
  ASSERT_TRUE(tool.handleCommand("startAutoOptimize", { { "method", "UFF" } }));
  EXPECT_TRUE(tool.running());
  tool.stop();
}

TEST_F(AutoOptCommandTest, rejectedStartLeavesButtonStopped)
{
  auto* button = tool.toolWidget()->findChild<QPushButton*>("startStopButton");
  ASSERT_NE(button, nullptr);
  molecule.clearAtoms();
  tool.start();
  EXPECT_FALSE(tool.running());
  EXPECT_EQ(button->text(), "Start");
}

TEST_F(AutoOptCommandTest, immediateStopReleasesCalculator)
{
  ASSERT_TRUE(
    Avogadro::Calc::EnergyManager::registerModel(new TrackedCalculator));
  for (int i = 0; i < 50; ++i) {
    EXPECT_TRUE(tool.handleCommand("startAutoOptimize",
                                   { { "method", "AutoOptLifetimeTest" } }));
    // Do not wait for the worker's initialization event before stopping it.
    tool.stop();
    EXPECT_EQ(liveCalculators.load(), 1) << "restart " << i;
  }
  EXPECT_TRUE(
    Avogadro::Calc::EnergyManager::unregisterModel("AutoOptLifetimeTest"));
  EXPECT_EQ(liveCalculators.load(), 0);
}
