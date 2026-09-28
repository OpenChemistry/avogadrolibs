/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/io/gromacsformat.h>

#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Io::GromacsFormat;

namespace {

const std::string groAtoms = "silicon\n"
                             "1\n"
                             "    1Si      Si    1   0.200   0.200   0.200\n";

} // namespace

TEST(GromacsTest, readBox)
{
  GromacsFormat gro;
  Molecule molecule;
  ASSERT_TRUE(gro.readString(groAtoms + "0.400   0.400   0.400\n", molecule))
    << gro.error();

  EXPECT_EQ(molecule.atomCount(), 1);
  ASSERT_NE(molecule.unitCell(), nullptr);
  EXPECT_DOUBLE_EQ(molecule.unitCell()->a(), 4.0); // nm --> Angstrom
}

// Regression test: the box line is required, but a missing or blank one was
// accepted and the molecule read without a unit cell.
TEST(GromacsTest, missingBoxFails)
{
  GromacsFormat gro;
  Molecule molecule;
  EXPECT_FALSE(gro.readString(groAtoms, molecule));
}

TEST(GromacsTest, blankBoxFails)
{
  GromacsFormat gro;
  Molecule molecule;
  EXPECT_FALSE(gro.readString(groAtoms + "\n", molecule));
}
