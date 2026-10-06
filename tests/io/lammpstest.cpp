/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/lammpsformat.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Io::FileFormat;
using Avogadro::Io::LammpsDataFormat;
using Avogadro::Io::LammpsTrajectoryFormat;

TEST(LammpsTest, read)
{
  LammpsTrajectoryFormat multi;
  multi.open(AVOGADRO_DATA "/data/silicon_bulk.dump",
             FileFormat::Read | FileFormat::MultiMolecule);
  Molecule molecule, molecule2;

  // Read in the structure.
  EXPECT_TRUE(multi.readMolecule(molecule));
  ASSERT_EQ(multi.error(), "");

  // First, let's check the unit cell
  UnitCell* uc = molecule.unitCell();
  bool status = true;

  EXPECT_EQ(uc->aVector(),
            Vector3(2.7155000000000001e+01, 0.00000000, 0.00000000));
  EXPECT_EQ(uc->bVector(),
            Vector3(0.00000000, 2.7155000000000001e+01, 0.00000000));
  EXPECT_EQ(uc->cVector(),
            Vector3(0.00000000, 0.00000000, 2.7155000000000001e+01));

  // Check that the number of atoms per step and number of steps in the
  // trajectory were read correctly
  EXPECT_EQ(molecule.atomCount(), 1000);
  EXPECT_EQ(molecule.coordinate3dCount(), 11);

  // First frame
  EXPECT_EQ(molecule.timeStep(0, status), 0);

  // Check a couple of positions to make sure they were read correctly
  EXPECT_EQ(molecule.atom(1).position3d().x(), 1.35775);
  EXPECT_EQ(molecule.atom(1).position3d().y(), 1.35775);
  EXPECT_EQ(molecule.atom(1).position3d().z(), 1.35775);
  EXPECT_EQ(molecule.atom(4).position3d().x(), 10.862);
  EXPECT_EQ(molecule.atom(4).position3d().y(), 0);
  EXPECT_EQ(molecule.atom(4).position3d().z(), 0);

  // Switching to second frame
  EXPECT_TRUE(molecule.setCoordinate3d(1));
  EXPECT_EQ(molecule.timeStep(1, status), 10);

  // Check a couple of positions to make sure they were read correctly
  EXPECT_EQ(molecule.atom(1).position3d().x(), 1.34317);
  EXPECT_EQ(molecule.atom(1).position3d().y(), 1.30464);
  EXPECT_EQ(molecule.atom(1).position3d().z(), 1.42722);
  EXPECT_EQ(molecule.atom(4).position3d().x(), 10.7867);
  EXPECT_EQ(molecule.atom(4).position3d().y(), -0.0484348);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.0809766);

  // Switching to last frame
  EXPECT_TRUE(molecule.setCoordinate3d(10));
  EXPECT_EQ(molecule.timeStep(10, status), 100);

  // Check a couple of positions to make sure they were read correctly
  EXPECT_EQ(molecule.atom(1).position3d().x(), 1.37614);
  EXPECT_EQ(molecule.atom(1).position3d().y(), 1.34302);
  EXPECT_EQ(molecule.atom(1).position3d().z(), 1.39375);
  EXPECT_EQ(molecule.atom(4).position3d().x(), 10.6846);
  EXPECT_EQ(molecule.atom(4).position3d().y(), -0.0479311);
  EXPECT_EQ(molecule.atom(4).position3d().z(), -0.0770097);
}

TEST(LammpsTest, modes)
{
  // This tests some of the mode setting/checking code
  LammpsTrajectoryFormat format;
  format.open(AVOGADRO_DATA "/data/silicon_bulk.dump", FileFormat::Read);
  EXPECT_TRUE(format.isMode(FileFormat::Read));
  EXPECT_TRUE(format.mode() & FileFormat::Read);
  EXPECT_FALSE(format.isMode(FileFormat::Write));

  // Try some combinations now.
  format.open(AVOGADRO_DATA "/data/silicon_bulk.dump",
              FileFormat::Read | FileFormat::MultiMolecule);
  EXPECT_TRUE(format.isMode(FileFormat::Read));
  EXPECT_TRUE(format.isMode(FileFormat::Read | FileFormat::MultiMolecule));
  EXPECT_TRUE(format.isMode(FileFormat::MultiMolecule));
}

TEST(LammpsTest, write)
{
  Molecule molecule;
  molecule.addAtom(5).setPosition3d(Vector3(1.2, 1.6, 2.0));
  molecule.addAtom(7).setPosition3d(Vector3(3.0, 2.4, 2.5));

  {
    LammpsDataFormat lmpdat;
    molecule.setData("name", "left-handed system [j, i, k]");
    auto* const uc =
      new UnitCell({ 0.0, 4.0, 0.0 }, { 5.0, 0.0, 0.0 }, { 0.0, 0.0, 6.0 });
    molecule.setUnitCell(uc);

    std::string output;
    ASSERT_TRUE(lmpdat.writeString(output, molecule));
    EXPECT_EQ(output, R"(left-handed system [j, i, k]
2 atoms
0 bonds
2 atom types
  0.000000   4.000000 xlo xhi
  0.000000   5.000000 ylo yhi
  0.000000   6.000000 zlo zhi
  0.000000   0.000000   0.000000 xy xz yz


Masses

1   10.81
2   14.007



Atoms

1 1   1.600000   1.200000   2.000000
2 2   2.400000   3.000000   2.500000


)");
  }

  {
    LammpsDataFormat lmpdat;
    molecule.setData("name", "right-handed silicon primitive cell");
    auto* const uc =
      new UnitCell({ 0.0, 2.0, 2.0 }, { 2.0, 0.0, 2.0 }, { 2.0, 2.0, 0.0 });
    molecule.setUnitCell(uc);

    std::string output;
    ASSERT_TRUE(lmpdat.writeString(output, molecule));
    EXPECT_EQ(output, R"(right-handed silicon primitive cell
2 atoms
0 bonds
2 atom types
  0.000000   2.828427 xlo xhi
  0.000000   2.449490 ylo yhi
  0.000000   2.309401 zlo zhi
  1.414214   1.414214   0.816497 xy xz yz


Masses

1   10.81
2   14.007



Atoms

1 1   2.545584   1.143095   0.461880
2 2   3.464823   2.490315   1.674316


)");
  }
}

// Regression test: a box-bounds row with too few fields was indexed with
// at(), which threw instead of reporting a format error.
TEST(LammpsTest, shortBoxBoundsRowFails)
{
  const std::string header = "ITEM: TIMESTEP\n0\nITEM: NUMBER OF ATOMS\n1\n";
  const std::string atoms = "ITEM: ATOMS id type x y z\n1 1 0.0 0.0 0.0\n";

  // Triclinic rows need lo, hi and a tilt factor.
  LammpsTrajectoryFormat triclinic;
  Molecule molecule;
  EXPECT_FALSE(triclinic.readString(header +
                                      "ITEM: BOX BOUNDS xy xz yz pp pp pp\n"
                                      "0.0 5.0 0.0\n0.0 5.0\n0.0 5.0 0.0\n" +
                                      atoms,
                                    molecule));

  // Orthogonal rows need lo and hi.
  LammpsTrajectoryFormat orthogonal;
  Molecule molecule2;
  EXPECT_FALSE(orthogonal.readString(
    header + "ITEM: BOX BOUNDS pp pp pp\n0.0 5.0\n0.0\n0.0 5.0\n" + atoms,
    molecule2));

  // Sanity check: the same file with complete rows reads.
  LammpsTrajectoryFormat valid;
  Molecule molecule3;
  EXPECT_TRUE(valid.readString(
    header + "ITEM: BOX BOUNDS pp pp pp\n0.0 5.0\n0.0 5.0\n0.0 5.0\n" + atoms,
    molecule3))
    << valid.error();
}

namespace {

const std::string kLammpsFrameHead =
  "ITEM: TIMESTEP\n0\nITEM: NUMBER OF ATOMS\n2\n"
  "ITEM: BOX BOUNDS pp pp pp\n0.0 5.0\n0.0 5.0\n0.0 5.0\n";
const std::string kLammpsFrameHead2 =
  "ITEM: TIMESTEP\n10\nITEM: NUMBER OF ATOMS\n2\n"
  "ITEM: BOX BOUNDS pp pp pp\n0.0 5.0\n0.0 5.0\n0.0 5.0\n";

bool readLammps(const std::string& input)
{
  LammpsTrajectoryFormat format;
  Molecule molecule;
  return format.readString(input, molecule);
}

} // namespace

// Regression test: the atom columns were indexed as header position minus
// two without checking that the header began with "ITEM: ATOMS", so a
// header without that prefix underflowed the unsigned index.
TEST(LammpsTest, malformedAtomsHeaderFails)
{
  const std::string rows = "1 1 0.0 0.0 0.0\n2 1 1.0 1.0 1.0\n";

  // No ITEM: ATOMS prefix at all -- x would be column 2, "index 0".
  EXPECT_FALSE(readLammps(kLammpsFrameHead + "id type x y z\n" + rows));
  // ITEM: without ATOMS.
  EXPECT_FALSE(readLammps(kLammpsFrameHead + "ITEM: id type x y z\n" + rows));
  // Missing x column.
  EXPECT_FALSE(
    readLammps(kLammpsFrameHead + "ITEM: ATOMS id type y z\n" + rows));
  // Column list too short to name anything.
  EXPECT_FALSE(readLammps(kLammpsFrameHead + "ITEM: ATOMS\n" + rows));
  EXPECT_FALSE(readLammps(kLammpsFrameHead + "ITEM:\n" + rows));
  EXPECT_FALSE(readLammps(kLammpsFrameHead + "\n" + rows));

  // The same header malformed in a later frame.
  const std::string first =
    kLammpsFrameHead + "ITEM: ATOMS id type x y z\n" + rows;
  EXPECT_FALSE(readLammps(first + kLammpsFrameHead2 + "x y z type\n" + rows));
  EXPECT_FALSE(
    readLammps(first + kLammpsFrameHead2 + "ITEM: ATOMS id type x z\n" + rows));

  // Sanity check: the well-formed version reads both frames.
  LammpsTrajectoryFormat valid;
  Molecule molecule;
  EXPECT_TRUE(valid.readString(
    first + kLammpsFrameHead2 + "ITEM: ATOMS id type x y z\n" + rows, molecule))
    << valid.error();
  EXPECT_EQ(molecule.atomCount(), 2);
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
}

// Regression test: an atom row shorter than the header declares must be
// rejected rather than read past its end.
TEST(LammpsTest, shortAtomRowFails)
{
  // The coordinates sit in the last three of six declared columns.
  const std::string header = "ITEM: ATOMS id type q x y z\n";
  const std::string rows = "1 1 0.5 0.0 0.0 0.0\n2 1 -0.5 1.0 1.0 1.0\n";
  const std::string shortRows = "1 1 0.5 0.0 0.0 0.0\n2 1 -0.5 1.0 1.0\n";

  // First frame.
  EXPECT_FALSE(readLammps(kLammpsFrameHead + header + shortRows));

  // A later frame. Five tokens used to be enough there whatever the header
  // said, so z (the sixth column) was read from past the end of the row.
  EXPECT_FALSE(readLammps(kLammpsFrameHead + header + rows + kLammpsFrameHead2 +
                          header + shortRows));

  // Sanity check: complete rows read, and x/y/z come from the right columns.
  LammpsTrajectoryFormat valid;
  Molecule molecule;
  ASSERT_TRUE(valid.readString(kLammpsFrameHead + header + rows +
                                 kLammpsFrameHead2 + header + rows,
                               molecule))
    << valid.error();
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
  EXPECT_EQ(molecule.atom(1).position3d(), Vector3(1.0, 1.0, 1.0));
}

// Scaled (fractional) coordinates are unscaled against the box bounds.
TEST(LammpsTest, scaledCoordinates)
{
  LammpsTrajectoryFormat format;
  Molecule molecule;
  ASSERT_TRUE(
    format.readString("ITEM: TIMESTEP\n0\nITEM: NUMBER OF ATOMS\n1\n"
                      "ITEM: BOX BOUNDS pp pp pp\n1.0 5.0\n0.0 10.0\n-2.0 2.0\n"
                      "ITEM: ATOMS id type xs ys zs\n1 1 0.5 0.25 0.75\n",
                      molecule))
    << format.error();
  EXPECT_EQ(molecule.atom(0).position3d(), Vector3(3.0, 2.5, 1.0));
}

namespace {

// Fails, and through the parser's own error rather than an exception caught
// by FileFormat's guard (which fuzz builds compile out).
::testing::AssertionResult readFailsCleanly(const std::string& input)
{
  LammpsTrajectoryFormat format;
  Molecule molecule;
  if (format.readString(input, molecule))
    return ::testing::AssertionFailure() << "read succeeded";
  if (format.error().find("appears to be malformed") != std::string::npos)
    return ::testing::AssertionFailure()
           << "read threw an exception: " << format.error();
  return ::testing::AssertionSuccess();
}

} // namespace

// Orthogonal boxes have two-column bound rows; triclinic boxes add a tilt
// factor as a third column. Both must give the right cell, and a two-column
// row under a triclinic header (in any frame) must fail rather than throw.
TEST(LammpsTest, boxBoundsColumns)
{
  const std::string head = "ITEM: TIMESTEP\n0\nITEM: NUMBER OF ATOMS\n1\n";
  const std::string head2 = "ITEM: TIMESTEP\n10\nITEM: NUMBER OF ATOMS\n1\n";
  const std::string atoms = "ITEM: ATOMS id type x y z\n1 1 0.5 0.5 0.5\n";
  const std::string ortho =
    "ITEM: BOX BOUNDS pp pp pp\n1.0 6.0\n-2.0 2.0\n0.0 3.5\n";
  const std::string tri =
    "ITEM: BOX BOUNDS xy xz yz pp pp pp\n0.0 5.5 0.5\n0.0 4.0 0.0\n"
    "0.0 3.0 0.0\n";

  // Two-column orthogonal rows.
  {
    LammpsTrajectoryFormat format;
    Molecule molecule;
    ASSERT_TRUE(format.readString(head + ortho + atoms, molecule))
      << format.error();
    ASSERT_NE(molecule.unitCell(), nullptr);
    EXPECT_EQ(molecule.unitCell()->aVector(), Vector3(5.0, 0.0, 0.0));
    EXPECT_EQ(molecule.unitCell()->bVector(), Vector3(0.0, 4.0, 0.0));
    EXPECT_EQ(molecule.unitCell()->cVector(), Vector3(0.0, 0.0, 3.5));
  }

  // Three-column triclinic rows: the x bounding box shrinks by the tilt.
  {
    LammpsTrajectoryFormat format;
    Molecule molecule;
    ASSERT_TRUE(format.readString(head + tri + atoms, molecule))
      << format.error();
    ASSERT_NE(molecule.unitCell(), nullptr);
    EXPECT_EQ(molecule.unitCell()->aVector(), Vector3(5.0, 0.0, 0.0));
    EXPECT_EQ(molecule.unitCell()->bVector(), Vector3(0.5, 4.0, 0.0));
    EXPECT_EQ(molecule.unitCell()->cVector(), Vector3(0.0, 0.0, 3.0));
  }

  // Triclinic header, but every row has only two columns.
  const std::string triShort =
    "ITEM: BOX BOUNDS xy xz yz pp pp pp\n0.0 5.0\n0.0 4.0\n0.0 3.0\n";
  EXPECT_TRUE(readFailsCleanly(head + triShort + atoms));
  // Only the z row is short.
  EXPECT_TRUE(readFailsCleanly(head +
                               "ITEM: BOX BOUNDS xy xz yz pp pp pp\n"
                               "0.0 5.0 0.0\n0.0 4.0 0.0\n0.0 3.0\n" +
                               atoms));
  // The same in a later frame, triclinic and orthogonal.
  EXPECT_TRUE(
    readFailsCleanly(head + ortho + atoms + head2 + triShort + atoms));
  EXPECT_TRUE(readFailsCleanly(head + ortho + atoms + head2 +
                               "ITEM: BOX BOUNDS pp pp pp\n1.0 6.0\n-2.0\n"
                               "0.0 3.5\n" +
                               atoms));
  // Box bounds cut off by the end of the file.
  EXPECT_TRUE(readFailsCleanly(head + "ITEM: BOX BOUNDS pp pp pp\n1.0 6.0\n"));
  EXPECT_TRUE(readFailsCleanly(
    head + "ITEM: BOX BOUNDS xy xz yz pp pp pp\n0.0 5.5 0.5\n"));

  // Sanity check: a two-frame file mixing both box kinds reads.
  LammpsTrajectoryFormat valid;
  Molecule molecule;
  ASSERT_TRUE(
    valid.readString(head + ortho + atoms + head2 + tri + atoms, molecule))
    << valid.error();
  EXPECT_EQ(molecule.coordinate3dCount(), 2);
  // The cell from the last frame read is the triclinic one.
  EXPECT_EQ(molecule.unitCell()->bVector(), Vector3(0.5, 4.0, 0.0));
}
