/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "applycolors.h"

#include <gtest/gtest.h>

using Avogadro::QtPlugins::ApplyColors;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

class ApplyColorsCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildMethanol();
    m_harness.attach(&m_applyColors);
    m_harness.registerCommands();
  }

  ApplyColors m_applyColors;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(ApplyColorsCommandTest, registersDocumentedCommands)
{
  const QStringList expected = {
    "colorAtomsCustom",     "resetAtomColors",
    "colorResiduesCustom",  "colorResiduesByAminoAcid",
    "colorResiduesShapely", "colorResiduesBySecondaryStructure",
    "resetResidueColors",   "colorAtomsByIndex",
    "colorAtomsByDistance", "colorAtomsByCharge"
  };

  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  for (const QString& name : expected)
    EXPECT_TRUE(registered.contains(name)) << name.toStdString();
}

TEST_F(ApplyColorsCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name :
       { "notACommand", "ColorAtomsCustom", "measureDistance" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::NotHandled) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

TEST_F(ApplyColorsCommandTest, noMoleculeFails)
{
  m_harness.setPluginMolecule(nullptr);
  for (const char* name :
       { "colorAtomsCustom", "resetAtomColors", "colorAtomsByIndex",
         "colorAtomsByDistance", "colorAtomsByCharge" }) {
    const CommandOutcome out = m_harness.run(name, { { "color", "#ff0000" } });
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_EQ(out.message, QString(NoMoleculeMessage)) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
}

// --- Custom color tests ---

TEST_F(ApplyColorsCommandTest, colorAtomsCustomValid)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsCustom", { { "color", "#00ff00" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
  EXPECT_EQ(m_harness.molecule()->colors()[0], Avogadro::Vector3ub(0, 255, 0));
}

TEST_F(ApplyColorsCommandTest, colorAtomsCustomInvalidColor)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsCustom", { { "color", "not_a_valid_color" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(ApplyColorsCommandTest, colorAtomsCustomMissingColor)
{
  const CommandOutcome out = m_harness.run("colorAtomsCustom");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

// --- Index colormap tests ---

TEST_F(ApplyColorsCommandTest, colorAtomsByIndexValid)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsByIndex", { { "colormap", "Viridis" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

TEST_F(ApplyColorsCommandTest, colorAtomsByIndexDefault)
{
  const CommandOutcome out = m_harness.run("colorAtomsByIndex");
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

TEST_F(ApplyColorsCommandTest, colorAtomsByIndexInvalidColormap)
{
  const CommandOutcome out = m_harness.run(
    "colorAtomsByIndex", { { "colormap", "InvalidColormapName" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

TEST_F(ApplyColorsCommandTest, colorAtomsByIndexTypoSuggestion)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsByIndex", { { "colormap", "jst" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_TRUE(out.message.contains("Did you mean \"Jet\"?")) << describe(out);
}

TEST_F(ApplyColorsCommandTest, colorAtomsByIndexNormalizedNames)
{
  const CommandOutcome out1 =
    m_harness.run("colorAtomsByIndex", { { "colormap", "blue-darkred" } });
  EXPECT_TRUE(out1.claimed);
  EXPECT_EQ(out1.status, CommandStatus::Finished) << describe(out1);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());

  const CommandOutcome out2 =
    m_harness.run("colorAtomsByIndex", { { "colormap", "blue_darkred" } });
  EXPECT_TRUE(out2.claimed);
  EXPECT_EQ(out2.status, CommandStatus::Finished) << describe(out2);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());

  const CommandOutcome out3 =
    m_harness.run("colorAtomsByIndex", { { "colormap", "bluedkred" } });
  EXPECT_TRUE(out3.claimed);
  EXPECT_EQ(out3.status, CommandStatus::Finished) << describe(out3);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

// --- Distance colormap tests ---

TEST_F(ApplyColorsCommandTest, colorAtomsByDistanceValid)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsByDistance", { { "colormap", "Magma" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

TEST_F(ApplyColorsCommandTest, colorAtomsByDistanceInvalidColormap)
{
  const CommandOutcome out = m_harness.run(
    "colorAtomsByDistance", { { "colormap", "InvalidColormap" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}

// --- Charge colormap tests ---

TEST_F(ApplyColorsCommandTest, colorAtomsByChargeNoChargesAvailable)
{
  const CommandOutcome out =
    m_harness.run("colorAtomsByCharge", { { "colormap", "Coolwarm" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_EQ(out.message, "No charge models available for this molecule.");
}

TEST_F(ApplyColorsCommandTest, colorAtomsByChargeValid)
{
  Avogadro::MatrixX charges(6, 1);
  charges << -0.4f, 0.2f, 0.05f, 0.05f, 0.05f, 0.05f;
  m_harness.molecule()->setPartialCharges("gasteiger", charges);

  const CommandOutcome out =
    m_harness.run("colorAtomsByCharge", { { "colormap", "Coolwarm" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

TEST_F(ApplyColorsCommandTest, colorAtomsByChargeExplicitModel)
{
  Avogadro::MatrixX charges(6, 1);
  charges << -0.4f, 0.2f, 0.05f, 0.05f, 0.05f, 0.05f;
  m_harness.molecule()->setPartialCharges("gasteiger", charges);

  const CommandOutcome out =
    m_harness.run("colorAtomsByCharge",
                  { { "colormap", "Coolwarm" }, { "model", "gasteiger" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_EQ(m_harness.molecule()->colors().size(),
            m_harness.molecule()->atomCount());
}

TEST_F(ApplyColorsCommandTest, colorAtomsByChargeInvalidModel)
{
  const CommandOutcome out = m_harness.run(
    "colorAtomsByCharge", { { "model", "NonexistentChargeModel" } });
  EXPECT_TRUE(out.claimed);
  EXPECT_EQ(out.status, CommandStatus::Failed) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
}
