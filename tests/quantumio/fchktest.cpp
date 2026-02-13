/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussianfchk.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::GaussianFchk;

// does the basic read work
TEST(GaussianFchkTest, basicRead)
{
  GaussianFchk format;
  Molecule molecule;
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/fchk/h2o-restricted.fchk", molecule));
  ASSERT_EQ(format.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 3);
}

// Regression test: oversized array header should fail gracefully.
TEST(GaussianFchkTest, oversizedArrayRejected)
{
  GaussianFchk format;
  Molecule molecule;

  std::ostringstream out;
  out << "Header line 1\n";
  out << "Header line 2\n";
  out << std::left << std::setw(42) << "Atomic numbers"
      << " I 20000000\n";

  EXPECT_FALSE(format.readString(out.str(), molecule));
  EXPECT_NE(format.error(), std::string());
}
