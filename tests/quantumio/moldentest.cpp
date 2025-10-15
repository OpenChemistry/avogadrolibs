/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/molden.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::MoldenFile;

// does the basic read work
TEST(MoldenTest, basicRead)
{
  MoldenFile format;
  Molecule molecule;
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 3);
}
