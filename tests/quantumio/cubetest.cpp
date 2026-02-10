/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussiancube.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::GaussianCube;

// does the basic read work
TEST(GaussianCubeTest, basicRead)
{
  GaussianCube cube;
  Molecule molecule;
  EXPECT_TRUE(
    cube.readFile(AVOGADRO_DATA "/data/cube/cn9-homo.cube", molecule));
  ASSERT_EQ(cube.error(), std::string());
}

// Regression test: malformed header should fail gracefully.
TEST(GaussianCubeTest, invalidHeaderDoesNotCrash)
{
  GaussianCube cube;
  Molecule molecule;

  EXPECT_FALSE(cube.readString("", molecule));
  EXPECT_NE(cube.error(), std::string());
}

// Regression test: oversized cube dimensions should fail gracefully.
TEST(GaussianCubeTest, oversizedCubeRejected)
{
  GaussianCube cube;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "0 0 0 0\n";
  out << "512 1 0 0\n";
  out << "512 0 1 0\n";
  out << "512 0 0 1\n";

  EXPECT_FALSE(cube.readString(out.str(), molecule));
  EXPECT_NE(cube.error(), std::string());
}
