/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "centroid.h"

#include <gtest/gtest.h>

#include <cmath>
#include <memory>
#include <vector>

using Avogadro::Index;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::QtPlugins::Centroid;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::NoMoleculeMessage;

namespace {

constexpr Real Tol = 1e-4;

::testing::AssertionResult nearVec(const Vector3& actual,
                                   const Vector3& expected)
{
  if ((actual - expected).cwiseAbs().maxCoeff() <= Tol)
    return ::testing::AssertionSuccess();
  return ::testing::AssertionFailure()
         << "got (" << actual.x() << ", " << actual.y() << ", " << actual.z()
         << "), expected (" << expected.x() << ", " << expected.y() << ", "
         << expected.z() << ")";
}

class CentroidCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_centroid = std::make_unique<Centroid>();
    m_harness.buildEmpty();
    m_harness.attach(m_centroid.get());
    m_harness.registerCommands();
  }

  std::unique_ptr<Centroid> m_centroid;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(CentroidCommandTest, registersDocumentedCommands)
{
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(registered.contains(QStringLiteral("addCentroid")));
  EXPECT_TRUE(registered.contains(QStringLiteral("addCenterOfMass")));
  EXPECT_TRUE(registered.contains(QStringLiteral("addPerpendicular")));
}

TEST_F(CentroidCommandTest, noMoleculeReturnsError)
{
  m_harness.setPluginMolecule(nullptr);
  for (const auto& cmd :
       { "addCentroid", "addCenterOfMass", "addPerpendicular" }) {
    const auto outcome = m_harness.run(cmd);
    EXPECT_EQ(outcome.status, CommandStatus::Failed)
      << cmd << ": " << describe(outcome);
    EXPECT_EQ(outcome.message, QString::fromLatin1(NoMoleculeMessage))
      << cmd << ": " << describe(outcome);
  }
}

TEST_F(CentroidCommandTest, rejectsUnknownOption)
{
  QVariantMap badOptions;
  badOptions.insert(QStringLiteral("extra"), 42);
  const auto outcome = m_harness.run("addCentroid", badOptions);
  EXPECT_EQ(outcome.status, CommandStatus::Failed) << describe(outcome);
}

TEST_F(CentroidCommandTest, emptyMoleculeFailsCleanly)
{
  for (const auto& cmd :
       { "addCentroid", "addCenterOfMass", "addPerpendicular" }) {
    const auto outcome = m_harness.run(cmd);
    EXPECT_EQ(outcome.status, CommandStatus::Failed)
      << cmd << ": " << describe(outcome);
  }
}

TEST_F(CentroidCommandTest, dummyAtomsOnlyFailsCleanly)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(0, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(0, Vector3(2.0, 0.0, 0.0));

  for (const auto& cmd :
       { "addCentroid", "addCenterOfMass", "addPerpendicular" }) {
    const auto outcome = m_harness.run(cmd);
    EXPECT_EQ(outcome.status, CommandStatus::Failed)
      << cmd << ": " << describe(outcome);
  }
}

TEST_F(CentroidCommandTest, addCentroidComputesGeometricCenter)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));

  const auto outcome = m_harness.run("addCentroid");
  EXPECT_EQ(outcome.status, CommandStatus::Finished) << describe(outcome);
  EXPECT_EQ(outcome.result.value(QStringLiteral("index")).toLongLong(), 2);

  const auto posList =
    outcome.result.value(QStringLiteral("position")).toList();
  ASSERT_EQ(posList.size(), 3);
  Vector3 pos(posList[0].toDouble(), posList[1].toDouble(),
              posList[2].toDouble());
  EXPECT_TRUE(nearVec(pos, Vector3(1.0, 0.0, 0.0)));

  EXPECT_EQ(mol->atomCount(), 3);
  EXPECT_EQ(mol->atomicNumber(2), 0);
  EXPECT_TRUE(nearVec(mol->atomPosition3d(2), Vector3(1.0, 0.0, 0.0)));
}

TEST_F(CentroidCommandTest, addCentroidHonorsSelection)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(10.0, 10.0, 10.0));

  mol->setAtomSelected(0, true);
  mol->setAtomSelected(1, true);
  mol->setAtomSelected(2, false);

  const auto outcome = m_harness.run("addCentroid");
  EXPECT_EQ(outcome.status, CommandStatus::Finished) << describe(outcome);

  const auto posList =
    outcome.result.value(QStringLiteral("position")).toList();
  ASSERT_EQ(posList.size(), 3);
  Vector3 pos(posList[0].toDouble(), posList[1].toDouble(),
              posList[2].toDouble());
  EXPECT_TRUE(nearVec(pos, Vector3(1.0, 0.0, 0.0)));
}

TEST_F(CentroidCommandTest, addCenterOfMassComputesMassWeightedCenter)
{
  auto* mol = m_harness.molecule();
  // Carbon (atomic 6, mass ~12.011) at (0, 0, 0)
  // Oxygen (atomic 8, mass ~15.999) at (2, 0, 0)
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(8, Vector3(2.0, 0.0, 0.0));

  const auto outcome = m_harness.run("addCenterOfMass");
  EXPECT_EQ(outcome.status, CommandStatus::Finished) << describe(outcome);
  EXPECT_EQ(outcome.result.value(QStringLiteral("index")).toLongLong(), 2);

  const auto posList =
    outcome.result.value(QStringLiteral("position")).toList();
  ASSERT_EQ(posList.size(), 3);
  Vector3 pos(posList[0].toDouble(), posList[1].toDouble(),
              posList[2].toDouble());

  // Center of mass: (15.999 * 2.0) / (12.011 + 15.999) ≈ 1.14238
  const Real expectedX = (15.999 * 2.0) / (12.011 + 15.999);
  EXPECT_TRUE(nearVec(pos, Vector3(expectedX, 0.0, 0.0)));
}

TEST_F(CentroidCommandTest, addPerpendicularRequiresAtLeastThreeAtoms)
{
  auto* mol = m_harness.molecule();
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));

  const auto outcome = m_harness.run("addPerpendicular");
  EXPECT_EQ(outcome.status, CommandStatus::Failed) << describe(outcome);
}

TEST_F(CentroidCommandTest, addPerpendicularComputesNormal)
{
  auto* mol = m_harness.molecule();
  // Three points in XY plane (z = 0)
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(0.0, 2.0, 0.0));

  const auto outcome = m_harness.run("addPerpendicular");
  EXPECT_EQ(outcome.status, CommandStatus::Finished) << describe(outcome);
  EXPECT_EQ(outcome.result.value(QStringLiteral("index")).toLongLong(), 3);

  const auto posList =
    outcome.result.value(QStringLiteral("position")).toList();
  ASSERT_EQ(posList.size(), 3);
  Vector3 pos(posList[0].toDouble(), posList[1].toDouble(),
              posList[2].toDouble());

  // Plane normal should be along Z (|z| > 1.0)
  EXPECT_GT(std::abs(pos.z()), 1.0);
}

TEST_F(CentroidCommandTest, addPerpendicularSkipsDummyAtoms)
{
  auto* mol = m_harness.molecule();
  // Three points in XY plane (z = 0)
  mol->addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(2.0, 0.0, 0.0));
  mol->addAtom(6, Vector3(0.0, 2.0, 0.0));
  // Dummy atom far out along Z
  mol->addAtom(0, Vector3(0.0, 0.0, 100.0));

  const auto outcome = m_harness.run("addPerpendicular");
  EXPECT_EQ(outcome.status, CommandStatus::Finished) << describe(outcome);

  const auto posList =
    outcome.result.value(QStringLiteral("position")).toList();
  ASSERT_EQ(posList.size(), 3);
  Vector3 pos(posList[0].toDouble(), posList[1].toDouble(),
              posList[2].toDouble());

  // The normal calculated from the 3 real atoms in XY plane still has |z| > 1.0
  EXPECT_GT(std::abs(pos.z()), 1.0);
}
