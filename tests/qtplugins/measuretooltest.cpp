/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "measuretool.h"

#include <gtest/gtest.h>

#include <cmath>
#include <limits>
#include <vector>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::QtPlugins::MeasureTool;
using Avogadro::QtPluginsTests::CommandOutcome;
using Avogadro::QtPluginsTests::CommandStatus;
using Avogadro::QtPluginsTests::CommandTestHarness;
using Avogadro::QtPluginsTests::describe;
using Avogadro::QtPluginsTests::expectNear;
using Avogadro::QtPluginsTests::MoleculeSnapshot;
using Avogadro::QtPluginsTests::NoMoleculeMessage;
using Avogadro::QtPluginsTests::recordKnownDeviation;

// Golden values below are all for CommandTestHarness::buildPeroxideChain():
//   H0 (0, 1, 0), O1 (0, 0, 0), O2 (1.5, 0, 0), H3 (1.5, 0, 1)
// and derived by hand in the comment next to each. Positions and distances
// are compared to 1e-9 A, angles to 1e-6 degrees: the arithmetic is exact
// up to a handful of double roundings, so anything looser than that would
// hide a real error.
namespace {

constexpr double PosTol = 1e-9;
constexpr double AngleTol = 1e-6;

QVariantList atoms(std::initializer_list<qlonglong> ids)
{
  QVariantList list;
  for (qlonglong id : ids)
    list << id;
  return list;
}

class MeasureToolCommandTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildPeroxideChain();
    m_harness.attach(&m_tool);
    m_harness.registerCommands();
  }

  // Run a measurement and return its value, checking the command's shape.
  double measure(const char* command, const QVariantList& ids, const char* key)
  {
    const MoleculeSnapshot before = m_harness.snapshot();
    const CommandOutcome out = m_harness.run(command, { { "atoms", ids } });
    EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
    EXPECT_TRUE(out.clean()) << describe(out);
    EXPECT_EQ(out.result.value("atoms").toList(), ids);
    // A measurement changes nothing, undo stack included.
    EXPECT_EQ(m_harness.snapshot().differences(before), QStringList());
    return out.result.value(key).toDouble();
  }

  // Expect a recognized command to fail cleanly and leave everything alone.
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
    EXPECT_EQ(m_harness.snapshot().differences(before), QStringList()) << label;
  }

  Vector3 position(Index i) const
  {
    return m_harness.molecule()->atomPosition3d(i);
  }

  MeasureTool m_tool;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(MeasureToolCommandTest, registersDocumentedCommands)
{
  const QStringList expected = { "measureDistance", "measureAngle",
                                 "measureDihedral", "editDistance",
                                 "editAngle",       "editDihedral" };
  const auto registered = m_harness.registerCommands();
  EXPECT_TRUE(m_harness.registrationViolations().isEmpty())
    << m_harness.registrationViolations().join("; ").toStdString();
  EXPECT_EQ(registered.keys().size(), expected.size());
  for (const QString& name : expected)
    EXPECT_TRUE(registered.contains(name)) << name.toStdString();
}

TEST_F(MeasureToolCommandTest, measureDistance)
{
  // |O2 - O1| = |(1.5, 0, 0)| = 1.5
  EXPECT_NEAR(measure("measureDistance", atoms({ 1, 2 }), "distance"), 1.5,
              PosTol);
  // |H3 - H0| = |(1.5, -1, 1)| = sqrt(2.25 + 1 + 1) = sqrt(4.25)
  EXPECT_NEAR(measure("measureDistance", atoms({ 0, 3 }), "distance"),
              std::sqrt(4.25), PosTol);
}

TEST_F(MeasureToolCommandTest, measureAngle)
{
  // At O1: O1->H0 = (0, 1, 0), O1->O2 = (1.5, 0, 0); perpendicular.
  EXPECT_NEAR(measure("measureAngle", atoms({ 0, 1, 2 }), "angle"), 90.0,
              AngleTol);
  // At O2: O2->O1 = (-1.5, 0, 0), O2->H3 = (0, 0, 1); perpendicular.
  EXPECT_NEAR(measure("measureAngle", atoms({ 1, 2, 3 }), "angle"), 90.0,
              AngleTol);
}

TEST_F(MeasureToolCommandTest, measureDihedral)
{
  // b1 = O1-H0 = (0,-1,0), b2 = O2-O1 = (1.5,0,0), b3 = H3-O2 = (0,0,1).
  // n1 = b1 x b2 = (0,0,1.5), n2 = b2 x b3 = (0,-1.5,0).
  // atan2(|b2| b1.n2, n1.n2) = atan2(2.25, 0) = +90 (IUPAC sign: looking
  // down O1->O2, H0 at +y turns clockwise onto H3 at +z).
  EXPECT_NEAR(measure("measureDihedral", atoms({ 0, 1, 2, 3 }), "dihedral"),
              90.0, AngleTol);
  // Reversal reads the same dihedral.
  EXPECT_NEAR(measure("measureDihedral", atoms({ 3, 2, 1, 0 }), "dihedral"),
              90.0, AngleTol);
}

// editDistance moves the second atom's side of the bond along the bond:
// O2 and H3 translate by (2.0 - 1.5) along +x.
TEST_F(MeasureToolCommandTest, editDistanceUndoRedo)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run(
    "editDistance", { { "atoms", atoms({ 1, 2 }) }, { "value", 2.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_NEAR(out.result.value("distance").toDouble(), 2.0, PosTol);

  expectNear(position(0), Vector3(0.0, 1.0, 0.0), PosTol, "H0");
  expectNear(position(1), Vector3(0.0, 0.0, 0.0), PosTol, "O1");
  expectNear(position(2), Vector3(2.0, 0.0, 0.0), PosTol, "O2");
  expectNear(position(3), Vector3(2.0, 0.0, 1.0), PosTol, "H3");

  const MoleculeSnapshot edited = m_harness.snapshot();
  EXPECT_EQ(before.differences(edited, false), QStringList({ "coordinates" }));
  EXPECT_EQ(edited.undoCount, before.undoCount + 1) << "one undo step";

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(edited), QStringList());
}

// editAngle rotates the vertex's side of the first bond (O1, O2, H3) about
// O1, in the H0-O1-O2 plane (the xy plane), opening the angle by 30 degrees:
// a rotation of -30 degrees about +z. O2 (1.5, 0, 0) -> 1.5 (cos 30, -sin
// 30, 0) = (1.299038105676658, -0.75, 0); H3 keeps its z of 1.
TEST_F(MeasureToolCommandTest, editAngleUndoRedo)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run(
    "editAngle", { { "atoms", atoms({ 0, 1, 2 }) }, { "value", 120.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_NEAR(out.result.value("angle").toDouble(), 120.0, AngleTol);

  const double x = 1.5 * std::sqrt(3.0) / 2.0; // 1.299038105676658
  expectNear(position(0), Vector3(0.0, 1.0, 0.0), PosTol, "H0");
  expectNear(position(1), Vector3(0.0, 0.0, 0.0), PosTol, "O1");
  expectNear(position(2), Vector3(x, -0.75, 0.0), PosTol, "O2");
  expectNear(position(3), Vector3(x, -0.75, 1.0), PosTol, "H3");
  // The O1-O2 bond length is untouched by the rotation.
  EXPECT_NEAR(measure("measureDistance", atoms({ 1, 2 }), "distance"), 1.5,
              PosTol);

  const MoleculeSnapshot edited = m_harness.snapshot();
  EXPECT_EQ(edited.undoCount, before.undoCount + 1) << "one undo step";
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(edited), QStringList());
}

// Boundary: 180 degrees is accepted. A further 90 degree opening is a
// rotation of -90 degrees about +z: (x, y) -> (y, -x), so O2 -> (0, -1.5, 0)
// and H3 -> (0, -1.5, 1); H0-O1-O2 is then straight.
TEST_F(MeasureToolCommandTest, editAngleTo180IsAccepted)
{
  const CommandOutcome out = m_harness.run(
    "editAngle", { { "atoms", atoms({ 0, 1, 2 }) }, { "value", 180.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_NEAR(out.result.value("angle").toDouble(), 180.0, AngleTol);
  expectNear(position(2), Vector3(0.0, -1.5, 0.0), PosTol, "O2");
  expectNear(position(3), Vector3(0.0, -1.5, 1.0), PosTol, "H3");
}

// editDihedral turns the far side of the O1-O2 bond (O2, H3) about the bond.
// From +90 to +60 is a 30 degree turn of H3 back towards H0: H3's offset
// from O2, (0, 0, 1), becomes (0, sin 30, cos 30) = (0, 0.5, 0.866...).
// Check: n2 = b2 x b3 = (1.5,0,0) x (0,0.5,0.866) = (0,-1.299,0.75);
// atan2(1.5 * 1.299, n1.n2 = 1.125) = atan2(1.9486, 1.125) = 60 degrees.
TEST_F(MeasureToolCommandTest, editDihedralUndoRedo)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run(
    "editDihedral", { { "atoms", atoms({ 0, 1, 2, 3 }) }, { "value", 60.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_TRUE(out.clean()) << describe(out);
  EXPECT_NEAR(out.result.value("dihedral").toDouble(), 60.0, AngleTol);

  expectNear(position(0), Vector3(0.0, 1.0, 0.0), PosTol, "H0");
  expectNear(position(1), Vector3(0.0, 0.0, 0.0), PosTol, "O1");
  expectNear(position(2), Vector3(1.5, 0.0, 0.0), PosTol, "O2");
  expectNear(position(3), Vector3(1.5, 0.5, std::sqrt(3.0) / 2.0), PosTol,
             "H3");

  const MoleculeSnapshot edited = m_harness.snapshot();
  EXPECT_EQ(edited.undoCount, before.undoCount + 1) << "one undo step";
  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(before, false), QStringList());
  EXPECT_TRUE(m_harness.redo().isEmpty());
  EXPECT_EQ(m_harness.snapshot().differences(edited), QStringList());
}

// Release plan section 4.2: measureDistance -> editDistance -> undo.
TEST_F(MeasureToolCommandTest, measureEditUndoSequence)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  EXPECT_NEAR(measure("measureDistance", atoms({ 1, 2 }), "distance"), 1.5,
              PosTol);

  const CommandOutcome out = m_harness.run(
    "editDistance", { { "atoms", atoms({ 1, 2 }) }, { "value", 2.0 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  EXPECT_NEAR(measure("measureDistance", atoms({ 1, 2 }), "distance"), 2.0,
              PosTol);

  EXPECT_TRUE(m_harness.undo().isEmpty());
  EXPECT_NEAR(measure("measureDistance", atoms({ 1, 2 }), "distance"), 1.5,
              PosTol);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(after.differences(before, false), QStringList());
  EXPECT_EQ(after.undoIndex, before.undoIndex);
  EXPECT_EQ(after.undoCount, before.undoCount + 1) << "redo still possible";
}

TEST_F(MeasureToolCommandTest, invalidAtomListsAreRefused)
{
  const QVariantList tooFew = atoms({ 1 });
  const QVariantList tooMany = atoms({ 0, 1, 2 });
  const QVariantList text = { qlonglong(1), QStringLiteral("2") };
  const QVariantList boolean = { qlonglong(1), true };
  const QVariantList fractional = { qlonglong(1), 1.5 };
  const QVariantList notANumber = { qlonglong(1),
                                    std::numeric_limits<double>::quiet_NaN() };
  const std::vector<std::pair<std::string, QVariantMap>> cases = {
    { "missing atoms", {} },
    { "atoms not a list", { { "atoms", "1,2" } } },
    { "too few", { { "atoms", tooFew } } },
    { "too many", { { "atoms", tooMany } } },
    { "string index", { { "atoms", text } } },
    { "bool index", { { "atoms", boolean } } },
    { "fractional index", { { "atoms", fractional } } },
    { "NaN index", { { "atoms", notANumber } } },
    { "negative index", { { "atoms", atoms({ -1, 1 }) } } },
    { "index == atomCount", { { "atoms", atoms({ 1, 4 }) } } },
    { "huge index", { { "atoms", atoms({ 1, qlonglong(1) << 40 }) } } },
    { "repeated index", { { "atoms", atoms({ 1, 1 }) } } },
  };
  for (const auto& [label, options] : cases) {
    expectRefused("measureDistance", options, "measureDistance " + label);
    QVariantMap edit = options;
    edit.insert("value", 2.0);
    expectRefused("editDistance", edit, "editDistance " + label);
  }
  // Angle and dihedral counts are checked per command.
  expectRefused("measureAngle", { { "atoms", atoms({ 0, 1 }) } },
                "measureAngle with 2 atoms");
  expectRefused("measureDihedral", { { "atoms", atoms({ 0, 1, 2 }) } },
                "measureDihedral with 3 atoms");
}

TEST_F(MeasureToolCommandTest, invalidEditValuesAreRefused)
{
  const double nan = std::numeric_limits<double>::quiet_NaN();
  const double inf = std::numeric_limits<double>::infinity();
  const QVariantList pair = atoms({ 1, 2 });
  const QVariantList triple = atoms({ 0, 1, 2 });
  const QVariantList quad = atoms({ 0, 1, 2, 3 });

  expectRefused("editDistance", { { "atoms", pair } }, "missing value");
  expectRefused("editDistance", { { "atoms", pair }, { "value", "2.0" } },
                "string value");
  expectRefused("editDistance", { { "atoms", pair }, { "value", 0.0 } },
                "zero distance (boundary)");
  expectRefused("editDistance", { { "atoms", pair }, { "value", -1.0 } },
                "negative distance");
  expectRefused("editDistance", { { "atoms", pair }, { "value", nan } },
                "NaN distance");
  expectRefused("editDistance", { { "atoms", pair }, { "value", inf } },
                "infinite distance");

  expectRefused("editAngle", { { "atoms", triple }, { "value", -0.001 } },
                "angle below 0");
  expectRefused("editAngle", { { "atoms", triple }, { "value", 180.001 } },
                "angle above 180");
  expectRefused("editAngle", { { "atoms", triple }, { "value", nan } },
                "NaN angle");

  expectRefused("editDihedral", { { "atoms", quad } }, "missing dihedral");
  expectRefused("editDihedral", { { "atoms", quad }, { "value", inf } },
                "infinite dihedral");
}

// Valid indices and value, but no rigid fragment can move: refused, nothing
// moved.
TEST_F(MeasureToolCommandTest, editsWithoutARigidFragmentAreRefused)
{
  // H0 and O2 are in one molecule but not bonded.
  expectRefused("editDistance",
                { { "atoms", atoms({ 0, 2 }) }, { "value", 2.0 } },
                "unbonded pair in one molecule");
  // No O1-H3 bond for the dihedral to turn about.
  expectRefused("editDihedral",
                { { "atoms", atoms({ 0, 1, 3, 2 }) }, { "value", 60.0 } },
                "no central bond");
}

TEST_F(MeasureToolCommandTest, unknownCommandIsNotClaimed)
{
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name : { "notACommand", "MeasureDistance", "selectAll" }) {
    const CommandOutcome out = m_harness.run(name);
    EXPECT_FALSE(out.claimed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 1): true + commandFailed("No molecule"). MeasureTool
// claims and fails, as required, but with its own message.
TEST_F(MeasureToolCommandTest, knownDeviationNoMoleculeMessage)
{
  recordKnownDeviation("no molecule fails with \"There is no molecule to "
                       "measure.\" rather than \"No molecule\"");

  m_harness.setPluginMolecule(nullptr);
  const MoleculeSnapshot before = m_harness.snapshot();
  for (const char* name :
       { "measureDistance", "editDistance", "editAngle", "measureDihedral" }) {
    const CommandOutcome out =
      m_harness.run(name, { { "atoms", atoms({ 0, 1 }) }, { "value", 1.0 } });
    // The contract part, already met.
    EXPECT_TRUE(out.claimed) << name;
    EXPECT_EQ(out.status, CommandStatus::Failed) << name;
    EXPECT_TRUE(out.clean()) << name << ": " << describe(out);
    // The deviation: when this fails, expect NoMoleculeMessage.
    EXPECT_NE(out.message, QString(NoMoleculeMessage)) << name;
    EXPECT_EQ(out.message, QStringLiteral("There is no molecule to measure."))
      << name;
  }
  EXPECT_EQ(m_harness.snapshot(), before);
}

// Contract (decision 2): an edit that changes nothing must not push an undo
// entry. Setting a distance to its current value translates the fragment by
// exactly zero, but every atom's setPosition3d() still pushes a command.
TEST_F(MeasureToolCommandTest, knownDeviationNoOpEditPushesUndoEntry)
{
  recordKnownDeviation(
    "editDistance to the current value pushes an undo entry");

  const MoleculeSnapshot before = m_harness.snapshot();
  const CommandOutcome out = m_harness.run(
    "editDistance", { { "atoms", atoms({ 1, 2 }) }, { "value", 1.5 } });
  EXPECT_EQ(out.status, CommandStatus::Finished) << describe(out);
  const MoleculeSnapshot after = m_harness.snapshot();
  EXPECT_EQ(before.differences(after, false), QStringList());
  // When these fail, expect out.clean() and after == before.
  EXPECT_EQ(after.undoCount, before.undoCount + 1);
  EXPECT_FALSE(out.clean());
}
