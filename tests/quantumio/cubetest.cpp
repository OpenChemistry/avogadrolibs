/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussiancube.h>

#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

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

// Builds a minimal but complete one atom cube whose grid holds @p values.
static std::string makeCube(const std::vector<std::string>& values)
{
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    " << values.size() << "    0.100000    0.000000    0.000000\n";
  out << "    1    0.000000    0.100000    0.000000\n";
  out << "    1    0.000000    0.000000    0.100000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  for (const auto& value : values)
    out << "  " << value << "\n";
  return out.str();
}

// Regression test: values below FLT_MIN must not abort the read.
//
// Core::Cube stores float, and the stream extractor for float sets failbit
// when strtof reports ERANGE -- which includes a merely subnormal result. A
// Q-Chem cube whose density decayed past FLT_MIN in the last few grid points
// was rejected with "Invalid cube data" after reading 364719 of 364800 values.
TEST(GaussianCubeTest, subnormalValuesAreRead)
{
  GaussianCube cube;
  Molecule molecule;

  const std::string input = makeCube({ "1.000000000E-01", "9.293354777E-39",
                                       "6.601756585E-39", "1.505124610E-39" });

  ASSERT_TRUE(cube.readString(input, molecule));
  ASSERT_EQ(cube.error(), std::string());

  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));
  const auto* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), static_cast<size_t>(4));

  EXPECT_FLOAT_EQ((*values)[0], 1.0e-01f);
  // Subnormal, so compare against the narrowed value rather than exactly.
  EXPECT_NEAR((*values)[1], 9.293354777e-39f, 1.0e-40f);
  EXPECT_NEAR((*values)[2], 6.601756585e-39f, 1.0e-40f);
  EXPECT_NEAR((*values)[3], 1.505124610e-39f, 1.0e-40f);
}

// Regression test: an exponent too small even for double is still read as zero,
// and one too large is clamped rather than becoming an infinity.
TEST(GaussianCubeTest, outOfRangeExponentsAreClamped)
{
  GaussianCube cube;
  Molecule molecule;

  const std::string input =
    makeCube({ "1.0E-500", "-1.0E-500", "1.0E+500", "-1.0E+500" });

  ASSERT_TRUE(cube.readString(input, molecule));
  ASSERT_EQ(cube.error(), std::string());

  const auto* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), static_cast<size_t>(4));

  EXPECT_FLOAT_EQ((*values)[0], 0.0f);
  EXPECT_FLOAT_EQ((*values)[1], 0.0f);
  EXPECT_FALSE(std::isinf((*values)[2]));
  EXPECT_FALSE(std::isinf((*values)[3]));
  EXPECT_FLOAT_EQ((*values)[2], std::numeric_limits<float>::max());
  EXPECT_FLOAT_EQ((*values)[3], std::numeric_limits<float>::lowest());
}

// Tolerating range errors must not start accepting malformed data.
TEST(GaussianCubeTest, malformedValuesStillRejected)
{
  for (const std::string& bad :
       { std::string("1.5abc"), std::string("***********"), std::string("nan"),
         std::string("inf") }) {
    GaussianCube cube;
    Molecule molecule;
    const std::string input = makeCube({ "1.0E-01", bad, "1.0E-01" });
    EXPECT_FALSE(cube.readString(input, molecule)) << "accepted: " << bad;
    EXPECT_NE(cube.error(), std::string()) << "no error for: " << bad;
  }
}

// Regression test: binary junk input should fail gracefully.
TEST(GaussianCubeTest, binaryInputDoesNotCrash)
{
  GaussianCube cube;
  Molecule molecule;

  std::string input;
  input.push_back(static_cast<char>(0x61));
  input.push_back(static_cast<char>(0x25));
  input.push_back(static_cast<char>(0x01));
  input.push_back(static_cast<char>(0x00));
  input.push_back(static_cast<char>(0x00));
  input.push_back(static_cast<char>(0xdc));
  input.push_back(static_cast<char>(0x00));
  input.push_back(static_cast<char>(0x3f));

  EXPECT_FALSE(cube.readString(input, molecule));
  EXPECT_NE(cube.error(), std::string());
}
