/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

#include <avogadro/io/pdbformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::PdbFormat;

TEST(PdbTest, read)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1MYK.pdb", molecule);

  // how many atoms?
  EXPECT_EQ(molecule.atomCount(), 780);
  EXPECT_EQ(molecule.residueCount(), 108);
}

TEST(PdbTest, altLoc)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/1FDT.pdb", molecule);

  EXPECT_EQ(molecule.coordinate3dCount(), 2);

  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).x(),
                  molecule.coordinate3d(1)[264].x());
  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).y(),
                  molecule.coordinate3d(1)[264].y());
  EXPECT_FLOAT_EQ(molecule.atomPosition3d(264).z(),
                  molecule.coordinate3d(1)[264].z());

  EXPECT_TRUE(
    molecule.atomPosition3d(265).x() != molecule.coordinate3d(1)[265].x() ||
    molecule.atomPosition3d(265).y() != molecule.coordinate3d(1)[265].y() ||
    molecule.atomPosition3d(265).z() != molecule.coordinate3d(1)[265].z());
}

TEST(PdbTest, readVillin)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/villin_N68H.pdb",
               molecule);

  // how many atoms?
  EXPECT_EQ(molecule.atomCount(), 8867);
  EXPECT_EQ(molecule.residueCount(), 371);

  EXPECT_EQ(molecule.coordinate3dCount(), 10);
}

TEST(PdbTest, cryst1)
{
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst1.pdb", molecule);

  EXPECT_EQ(molecule.atomCount(), 7);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}

TEST(PdbTest, cryst2)
{
  // Crash fixed with #2182
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst2.pdb", molecule);

  EXPECT_EQ(molecule.atomCount(), 7);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}

TEST(PdbTest, cryst3)
{
  // Crash fixed with #2182
  PdbFormat pdb;
  Molecule molecule;
  pdb.readFile(std::string(AVOGADRO_DATA) + "/data/pdb/cryst3.pdb", molecule);

  EXPECT_EQ(molecule.atomCount(), 7);

  // make sure it has a unit cell
  bool hasUnitCell = (molecule.unitCell() != nullptr);
  EXPECT_TRUE(hasUnitCell);
}
