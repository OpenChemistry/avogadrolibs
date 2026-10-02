/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussiancube.h>

#include <algorithm>
#include <clocale>
#include <cmath>
#include <cstdio>
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

// Builds a one atom cube with @p count points along x whose data section is
// exactly @p dataText.
static std::string makeCubeWithData(size_t count, const std::string& dataText)
{
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    " << count << "    0.100000    0.000000    0.000000\n";
  out << "    1    0.000000    0.100000    0.000000\n";
  out << "    1    0.000000    0.000000    0.100000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  out << dataText << "\n";
  return out.str();
}

// CP2K writes Fortran E13.5 values with three digit exponents and no separator
// before a negative number, so one whitespace token holds several values.
TEST(GaussianCubeTest, runTogetherValuesAreRead)
{
  GaussianCube cube;
  Molecule molecule;

  const std::string input = makeCubeWithData(
    9, " 0.26189E-002-0.85098E-002-0.14043E-001-0.92412E-002 0.72516E-003 "
       "0.14311E-001\n -0.1E-048 0.5-0.25+0.75");

  ASSERT_TRUE(cube.readString(input, molecule)) << cube.error();
  ASSERT_EQ(cube.error(), std::string());
  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));
  const auto* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), static_cast<size_t>(9));

  EXPECT_FLOAT_EQ((*values)[0], 0.26189E-002f);
  EXPECT_FLOAT_EQ((*values)[1], -0.85098E-002f);
  EXPECT_FLOAT_EQ((*values)[2], -0.14043E-001f);
  EXPECT_FLOAT_EQ((*values)[3], -0.92412E-002f);
  EXPECT_FLOAT_EQ((*values)[4], 0.72516E-003f);
  EXPECT_FLOAT_EQ((*values)[5], 0.14311E-001f);
  // Underflows float entirely, so it is read as (negative) zero.
  EXPECT_FLOAT_EQ((*values)[6], 0.0f);
  // Plain decimals run together too, including a '+' separator.
  EXPECT_FLOAT_EQ((*values)[7], 0.5f);
  EXPECT_FLOAT_EQ((*values)[8], -0.25f);
}

// A subnormal value followed by a run-together negative value.
TEST(GaussianCubeTest, runTogetherSubnormalIsRead)
{
  GaussianCube cube;
  Molecule molecule;

  const std::string input =
    makeCubeWithData(3, " 0.15051E-039-0.20000E+001 0.30000E+000");
  ASSERT_TRUE(cube.readString(input, molecule)) << cube.error();
  const auto* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), static_cast<size_t>(3));
  EXPECT_NEAR((*values)[0], 0.15051e-039f, 1.0e-42f);
  EXPECT_GT((*values)[0], 0.0f);
  EXPECT_FLOAT_EQ((*values)[1], -2.0f);
  EXPECT_FLOAT_EQ((*values)[2], 0.3f);
}

// Splitting at a sign must not make the reader accept junk.
TEST(GaussianCubeTest, runTogetherDoesNotAcceptJunk)
{
  for (const std::string& bad :
       { std::string("*******"), std::string("1.5abc"),
         std::string("0.1E-002*****"), std::string("0.1-"),
         std::string("0.1-abc"), std::string("0.1-0.2x"),
         std::string("0.1E-002-nan") }) {
    GaussianCube cube;
    Molecule molecule;
    const std::string input = makeCubeWithData(3, " 0.5 " + bad + " 0.5");
    EXPECT_FALSE(cube.readString(input, molecule)) << "accepted: " << bad;
    EXPECT_NE(cube.error(), std::string()) << "no error for: " << bad;
  }
}

// Voxel axes that are not along x, y and z cannot be stored in a Core::Cube, so
// the reader resamples them onto an axis-aligned grid. A linear function is
// reproduced exactly by trilinear interpolation, so each resampled point inside
// the original grid must equal the function there, and each point outside zero.
TEST(GaussianCubeTest, skewedGridIsResampledExactly)
{
  using Avogadro::Matrix3;
  using Avogadro::Vector3i;
  constexpr double toAngstrom = Avogadro::BOHR_TO_ANGSTROM;

  const Vector3i n(6, 7, 5);
  // Step vectors (columns, bohr) shaped like a triclinic CP2K cell.
  Matrix3 steps;
  steps << 0.58, 0.21, -0.33, //
    0.0, 0.52, -0.13,         //
    0.0, 0.0, 0.50;
  const Vector3 origin(0.1, -0.2, 0.3); // bohr
  const Vector3 gradient(1.5, -0.75, 2.0);
  const double offset = 0.25;
  auto f = [&](const Vector3& rAngstrom) {
    return gradient.dot(rAngstrom) + offset;
  };

  std::ostringstream out;
  out << "Skewed test\nSecond line\n";
  char buffer[128];
  std::snprintf(buffer, sizeof(buffer), "%5d %12.6f %12.6f %12.6f\n", 1,
                origin(0), origin(1), origin(2));
  out << buffer;
  for (int i = 0; i < 3; ++i) {
    std::snprintf(buffer, sizeof(buffer), "%5d %12.6f %12.6f %12.6f\n", n(i),
                  steps(0, i), steps(1, i), steps(2, i));
    out << buffer;
  }
  out << "    6    0.000000    1.000000    2.000000    3.000000\n";
  int count = 0;
  for (int i = 0; i < n(0); ++i)
    for (int j = 0; j < n(1); ++j)
      for (int k = 0; k < n(2); ++k) {
        const Vector3 r = (origin + steps * Vector3(i, j, k)) * toAngstrom;
        std::snprintf(buffer, sizeof(buffer), "% .8E", f(r));
        out << buffer << ((++count % 6 == 0) ? "\n" : " ");
      }
  out << "\n";

  GaussianCube reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(out.str(), molecule)) << reader.error();
  ASSERT_EQ(reader.error(), std::string());

  // The atom is not moved by the resampling.
  ASSERT_EQ(molecule.atomCount(), static_cast<size_t>(1));
  const Vector3 atom = molecule.atom(0).position3d();
  EXPECT_NEAR(atom(0), 1.0 * toAngstrom, 1.0e-9);
  EXPECT_NEAR(atom(1), 2.0 * toAngstrom, 1.0e-9);
  EXPECT_NEAR(atom(2), 3.0 * toAngstrom, 1.0e-9);

  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);

  // Axis-aligned bounding box of the eight corners, shortest step as spacing.
  const Matrix3 stepsA = steps * toAngstrom;
  const Vector3 originA = origin * toAngstrom;
  Vector3 lo = originA, hi = originA;
  for (int corner = 0; corner < 8; ++corner) {
    const Vector3 idx((corner & 1) ? n(0) - 1 : 0, (corner & 2) ? n(1) - 1 : 0,
                      (corner & 4) ? n(2) - 1 : 0);
    const Vector3 r = originA + stepsA * idx;
    lo = lo.cwiseMin(r);
    hi = hi.cwiseMax(r);
  }
  const double h = std::min(
    { stepsA.col(0).norm(), stepsA.col(1).norm(), stepsA.col(2).norm() });
  EXPECT_NEAR(cube->spacing()(0), h, 1.0e-9);
  EXPECT_NEAR(cube->spacing()(1), h, 1.0e-9);
  EXPECT_NEAR(cube->spacing()(2), h, 1.0e-9);
  EXPECT_NEAR(cube->min()(0), lo(0), 1.0e-9);
  EXPECT_NEAR(cube->min()(1), lo(1), 1.0e-9);
  EXPECT_NEAR(cube->min()(2), lo(2), 1.0e-9);
  const Vector3i dim = cube->dimensions();
  for (int a = 0; a < 3; ++a) {
    EXPECT_EQ(dim(a),
              static_cast<int>(std::floor((hi(a) - lo(a)) / h + 1e-6)) + 1);
  }
  ASSERT_EQ(cube->data()->size(),
            static_cast<size_t>(dim(0)) * dim(1) * dim(2));

  const Matrix3 inverse = stepsA.inverse();
  size_t inside = 0, outside = 0;
  for (int ix = 0; ix < dim(0); ++ix)
    for (int iy = 0; iy < dim(1); ++iy)
      for (int iz = 0; iz < dim(2); ++iz) {
        const Vector3 r = lo + h * Vector3(ix, iy, iz);
        const Vector3 u = inverse * (r - originA);
        const float value = cube->value(ix, iy, iz);
        bool surelyInside = true, surelyOutside = false;
        for (int a = 0; a < 3; ++a) {
          if (u(a) < 1.0e-6 || u(a) > n(a) - 1 - 1.0e-6)
            surelyInside = false;
          if (u(a) < -1.0e-3 || u(a) > n(a) - 1 + 1.0e-3)
            surelyOutside = true;
        }
        if (surelyInside) {
          ++inside;
          EXPECT_NEAR(value, f(r), 1.0e-4) << ix << " " << iy << " " << iz;
        } else if (surelyOutside) {
          ++outside;
          EXPECT_EQ(value, 0.0f) << ix << " " << iy << " " << iz;
        }
      }
  // The test is only meaningful if both cases occur.
  EXPECT_GT(inside, static_cast<size_t>(50));
  EXPECT_GT(outside, static_cast<size_t>(50));
}

// A grid whose first axis runs backwards along x is not skewed, but it cannot
// be stored as is either (Core::Cube needs a positive spacing).
TEST(GaussianCubeTest, negativeAxisIsResampled)
{
  GaussianCube reader;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    4   -0.100000    0.000000    0.000000\n";
  out << "    1    0.000000    0.100000    0.000000\n";
  out << "    1    0.000000    0.000000    0.100000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  out << " 1.0E+00 2.0E+00 3.0E+00 4.0E+00\n";

  ASSERT_TRUE(reader.readString(out.str(), molecule)) << reader.error();
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);
  ASSERT_EQ(cube->dimensions()(0), 4);
  EXPECT_NEAR(cube->min()(0), -0.3 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  EXPECT_NEAR(cube->spacing()(0), 0.1 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  ASSERT_EQ(cube->data()->size(), static_cast<size_t>(4));
  EXPECT_NEAR((*cube->data())[0], 4.0f, 1.0e-5);
  EXPECT_NEAR((*cube->data())[1], 3.0f, 1.0e-5);
  EXPECT_NEAR((*cube->data())[2], 2.0f, 1.0e-5);
  EXPECT_NEAR((*cube->data())[3], 1.0f, 1.0e-5);
}

// Linearly dependent voxel axes cannot be resampled, and must be refused.
TEST(GaussianCubeTest, singularGridRejected)
{
  GaussianCube reader;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    2    0.100000    0.000000    0.000000\n";
  out << "    2    0.200000    0.000000    0.000000\n";
  out << "    2    0.000000    0.000000    0.100000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  out << " 1 2 3 4 5 6 7 8\n";
  EXPECT_FALSE(reader.readString(out.str(), molecule));
  EXPECT_NE(reader.error(), std::string());
}

namespace {

// Switches the C locale to one with a comma as the decimal separator, and
// restores the previous locale on destruction.
class CommaDecimalLocale
{
public:
  CommaDecimalLocale()
  {
    const char* current = std::setlocale(LC_ALL, nullptr);
    if (current != nullptr)
      m_previous = current;
    for (const char* name : { "de_DE.UTF-8", "de_DE.utf8", "de_DE" }) {
      if (std::setlocale(LC_ALL, name) != nullptr) {
        m_active = true;
        return;
      }
    }
  }

  ~CommaDecimalLocale() { std::setlocale(LC_ALL, m_previous.c_str()); }

  bool active() const { return m_active; }

private:
  std::string m_previous = "C";
  bool m_active = false;
};

} // namespace

// Qt calls setlocale(LC_ALL, "") on Unix. With a comma as the decimal
// separator strtod stopped at the '.' of every value, so every cube file failed
// with "Invalid cube data." Reading must not depend on the C locale.
TEST(GaussianCubeTest, readIsIndependentOfCommaDecimalLocale)
{
  const std::string path = AVOGADRO_DATA "/data/cube/benzene-homo.cube";

  // Read once in whatever locale the test runs in (normally "C").
  GaussianCube reference;
  Molecule expected;
  ASSERT_TRUE(reference.readFile(path, expected));
  ASSERT_EQ(expected.cubeCount(), static_cast<size_t>(1));
  const std::vector<float>* expectedValues = expected.cube(0)->data();
  ASSERT_NE(expectedValues, nullptr);
  ASSERT_FALSE(expectedValues->empty());

  CommaDecimalLocale locale;
  if (!locale.active())
    GTEST_SKIP() << "No de_DE locale is installed";

  GaussianCube cube;
  Molecule molecule;
  ASSERT_TRUE(cube.readFile(path, molecule)) << cube.error();
  ASSERT_EQ(cube.error(), std::string());
  ASSERT_EQ(molecule.atomCount(), expected.atomCount());
  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));

  const std::vector<float>* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), expectedValues->size());
  EXPECT_EQ(*values, *expectedValues);
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
