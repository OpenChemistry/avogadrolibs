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
    10, " 0.26189E-002-0.85098E-002-0.14043E-001-0.92412E-002 0.72516E-003 "
        "0.14311E-001\n -0.1E-048 0.1D-01-0.2D-01+0.3E+00");

  ASSERT_TRUE(cube.readString(input, molecule)) << cube.error();
  ASSERT_EQ(cube.error(), std::string());
  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));
  const auto* values = molecule.cube(0)->data();
  ASSERT_NE(values, nullptr);
  ASSERT_EQ(values->size(), static_cast<size_t>(10));

  EXPECT_FLOAT_EQ((*values)[0], 0.26189E-002f);
  EXPECT_FLOAT_EQ((*values)[1], -0.85098E-002f);
  EXPECT_FLOAT_EQ((*values)[2], -0.14043E-001f);
  EXPECT_FLOAT_EQ((*values)[3], -0.92412E-002f);
  EXPECT_FLOAT_EQ((*values)[4], 0.72516E-003f);
  EXPECT_FLOAT_EQ((*values)[5], 0.14311E-001f);
  // Underflows float entirely, so it is read as (negative) zero.
  EXPECT_FLOAT_EQ((*values)[6], 0.0f);
  // Fortran D exponents split too, including at a '+' sign.
  EXPECT_FLOAT_EQ((*values)[7], 0.1e-1f);
  EXPECT_FLOAT_EQ((*values)[8], -0.2e-1f);
  EXPECT_FLOAT_EQ((*values)[9], 0.3f);
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
         std::string("0.12345-102"), std::string("1-5"),
         std::string("0.5-0.25"), std::string("0.1-abc"),
         std::string("0.1-0.2x"), std::string("0.1E-002-nan") }) {
    GaussianCube cube;
    Molecule molecule;
    const std::string input = makeCubeWithData(3, " 0.5 " + bad + " 0.5");
    EXPECT_FALSE(cube.readString(input, molecule)) << "accepted: " << bad;
    EXPECT_NE(cube.error(), std::string()) << "no error for: " << bad;
  }
}

namespace {

// Writes a cube file whose grid has the given step vectors (columns, bohr)
// and holds the linear function f (of the position in Angstrom).
std::string makeSkewedCube(const Avogadro::Matrix3& steps,
                           const Avogadro::Vector3i& n, const Vector3& origin,
                           const Vector3& gradient, double offset)
{
  constexpr double toAngstrom = Avogadro::BOHR_TO_ANGSTROM;
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
        std::snprintf(buffer, sizeof(buffer), "% .8E",
                      gradient.dot(r) + offset);
        out << buffer << ((++count % 6 == 0) ? "\n" : " ");
      }
  out << "\n";
  return out.str();
}

} // namespace

// Voxel axes that are not along x, y and z are stored as they are: the step
// vectors end up in the cube, the grid has the dimensions of the file (no
// resampling) and the values are unchanged.
TEST(GaussianCubeTest, skewedGridIsReadWithItsSteps)
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

  GaussianCube reader;
  Molecule molecule;
  ASSERT_TRUE(reader.readString(
    makeSkewedCube(steps, n, origin, gradient, offset), molecule))
    << reader.error();
  ASSERT_EQ(reader.error(), std::string());

  // The atom is not moved.
  ASSERT_EQ(molecule.atomCount(), static_cast<size_t>(1));
  const Vector3 atom = molecule.atom(0).position3d();
  EXPECT_NEAR(atom(0), 1.0 * toAngstrom, 1.0e-9);
  EXPECT_NEAR(atom(1), 2.0 * toAngstrom, 1.0e-9);
  EXPECT_NEAR(atom(2), 3.0 * toAngstrom, 1.0e-9);

  ASSERT_EQ(molecule.cubeCount(), static_cast<size_t>(1));
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);
  EXPECT_FALSE(cube->isAxisAligned());
  EXPECT_EQ(cube->dimensions(), n);
  ASSERT_EQ(cube->data()->size(), static_cast<size_t>(6 * 7 * 5));
  EXPECT_TRUE(cube->steps().isApprox(steps * toAngstrom, 1.0e-12));
  EXPECT_TRUE(cube->min().isApprox(origin * toAngstrom, 1.0e-12));
  for (int a = 0; a < 3; ++a)
    EXPECT_NEAR(cube->spacing()(a), (steps.col(a) * toAngstrom).norm(),
                1.0e-12);

  // Every value is the function at its own grid point, and the cube
  // interpolates the (linear) function between the points.
  for (int i = 0; i < n(0); ++i)
    for (int j = 0; j < n(1); ++j)
      for (int k = 0; k < n(2); ++k) {
        const Vector3 r = (origin + steps * Vector3(i, j, k)) * toAngstrom;
        EXPECT_NEAR(cube->value(i, j, k), gradient.dot(r) + offset, 1.0e-4);
      }
  const Vector3 inside = (origin + steps * Vector3(2.3, 3.6, 1.4)) * toAngstrom;
  EXPECT_NEAR(cube->value(inside), gradient.dot(inside) + offset, 1.0e-4);
}

// A skewed cube survives a write and a read with its off-diagonal steps.
TEST(GaussianCubeTest, skewedGridRoundTrips)
{
  using Avogadro::Matrix3;
  using Avogadro::Vector3i;

  const Vector3i n(4, 3, 5);
  Matrix3 steps;
  steps << 0.60, 0.20, -0.10, //
    0.05, 0.50, 0.15,         //
    0.0, -0.25, 0.45;
  const Vector3 origin(-0.4, 0.2, 0.9);
  GaussianCube reader;
  Molecule first;
  ASSERT_TRUE(reader.readString(
    makeSkewedCube(steps, n, origin, Vector3(1.0, 2.0, -1.0), 0.5), first))
    << reader.error();

  GaussianCube writer;
  std::ostringstream written;
  ASSERT_TRUE(writer.write(written, first)) << writer.error();

  GaussianCube reader2;
  Molecule second;
  ASSERT_TRUE(reader2.readString(written.str(), second)) << reader2.error();
  ASSERT_EQ(second.cubeCount(), static_cast<size_t>(1));
  const auto* a = first.cube(0);
  const auto* b = second.cube(0);
  EXPECT_EQ(a->dimensions(), b->dimensions());
  // The file holds six decimals of bohr.
  EXPECT_TRUE(a->steps().isApprox(b->steps(), 1.0e-5));
  EXPECT_NEAR((a->min() - b->min()).norm(), 0.0, 1.0e-5);
  EXPECT_FALSE(b->isAxisAligned());
  ASSERT_EQ(a->data()->size(), b->data()->size());
  for (size_t i = 0; i < a->data()->size(); ++i)
    EXPECT_NEAR((*a->data())[i], (*b->data())[i],
                1.0e-4 * (1.0 + std::abs((*a->data())[i])));
}

// A grid whose first axis runs backwards along x is stored as it is, with a
// negative step: the first value stays at the origin.
TEST(GaussianCubeTest, negativeAxisIsKept)
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
  EXPECT_NEAR(cube->min()(0), 0.0, 1.0e-9);
  EXPECT_TRUE(cube->isAxisAligned());
  EXPECT_NEAR(cube->spacing()(0), -0.1 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  EXPECT_NEAR(cube->max()(0), -0.3 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  ASSERT_EQ(cube->data()->size(), static_cast<size_t>(4));
  EXPECT_NEAR((*cube->data())[0], 1.0f, 1.0e-5);
  EXPECT_NEAR((*cube->data())[3], 4.0f, 1.0e-5);
  // Positions follow the step, so interpolation works backwards too.
  EXPECT_NEAR(
    cube->value(Vector3(-0.15 * Avogadro::BOHR_TO_ANGSTROM, 0.0, 0.0)), 2.5f,
    1.0e-4);
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

// A single-point axis never steps along its vector, so a zero step there
// (a plane of values) is neither singular nor skewed.
TEST(GaussianCubeTest, singlePointAxisStepIgnored)
{
  GaussianCube reader;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    2    0.100000    0.000000    0.000000\n";
  out << "    2    0.000000    0.200000    0.000000\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  out << " 1.0 2.0 3.0 4.0\n";

  ASSERT_TRUE(reader.readString(out.str(), molecule)) << reader.error();
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->dimensions(), Avogadro::Vector3i(2, 2, 1));
  EXPECT_NEAR(cube->spacing()(0), 0.1 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  EXPECT_NEAR(cube->spacing()(1), 0.2 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  ASSERT_EQ(cube->data()->size(), static_cast<size_t>(4));
  EXPECT_NEAR((*cube->data())[3], 4.0f, 1.0e-5);
}

// A skewed plane with a zero step on its single-point axis keeps the steps
// of the axes it has.
TEST(GaussianCubeTest, skewedPlaneWithZeroStepIsRead)
{
  GaussianCube reader;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    3    0.200000    0.000000    0.000000\n";
  out << "    3    0.100000    0.200000    0.000000\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  out << " 1 1 1 1 1 1 1 1 1\n";

  ASSERT_TRUE(reader.readString(out.str(), molecule)) << reader.error();
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);
  EXPECT_EQ(cube->dimensions(), Avogadro::Vector3i(3, 3, 1));
  EXPECT_FALSE(cube->isAxisAligned());
  const Avogadro::Matrix3 steps = cube->steps();
  EXPECT_NEAR(steps(0, 0), 0.2 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  EXPECT_NEAR(steps(0, 1), 0.1 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  EXPECT_NEAR(steps(1, 1), 0.2 * Avogadro::BOHR_TO_ANGSTROM, 1.0e-9);
  ASSERT_EQ(cube->data()->size(), static_cast<size_t>(9));
  EXPECT_NEAR((*cube->data())[0], 1.0f, 1.0e-5);
}

// A step that is almost zero must not make the grid any larger than the
// file says.
TEST(GaussianCubeTest, skewedGridWithTinyStepStaysSmall)
{
  GaussianCube reader;
  Molecule molecule;
  std::ostringstream out;
  out << "Comment line\n";
  out << "Second comment line\n";
  out << "    1    0.000000    0.000000    0.000000\n";
  out << "    5    0.200000    0.000000    0.000000\n";
  out << "    4    0.000000   -1.0e-7      1.2e-7\n";
  out << "    3    0.000000    0.000000    0.200000\n";
  out << "    1    1.000000    0.000000    0.000000    0.000000\n";
  const size_t valueCount = 5 * 4 * 3;
  for (size_t i = 0; i < valueCount; ++i)
    out << " 1.0" << ((i % 6 == 5) ? "\n" : "");
  out << "\n";

  ASSERT_TRUE(reader.readString(out.str(), molecule)) << reader.error();
  const auto* cube = molecule.cube(0);
  ASSERT_NE(cube, nullptr);
  const Avogadro::Vector3i dim = cube->dimensions();
  const size_t points = static_cast<size_t>(dim(0)) * dim(1) * dim(2);
  EXPECT_EQ(points, valueCount);
  EXPECT_EQ(cube->data()->size(), points);
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
