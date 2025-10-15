/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/gradients.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/angletools.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/xyzformat.h>

#include <cmath>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::XyzFormat;

bool compareVectors(const Vector3& a, const Vector3& b)
{
  // are these components within 10% of each other?
  return std::fabs(a.x() - b.x()) < 0.1 * std::fabs(a.x()) &&
         std::fabs(a.y() - b.y()) < 0.1 * std::fabs(a.y()) &&
         std::fabs(a.z() - b.z()) < 0.1 * std::fabs(a.z());
}

// check numeric to analytic gradient for all atoms in a molecule
bool checkGradients(Eigen::VectorXd analytical, Eigen::VectorXd numeric)
{
  // atom count based on size
  int n = analytical.size() / 3;
  for (int i = 0; i < n; ++i) {
    if (!compareVectors(
          Vector3(analytical[3 * i], analytical[3 * i + 1],
                  analytical[3 * i + 2]),
          Vector3(numeric[3 * i], numeric[3 * i + 1], numeric[3 * i + 2]))) {
      return false;
    }
  }
  return true;
}

// basic idea - go through a bunch of molecules
// calculate gradients and numeric gradients
// make sure the gradients are close for each atom

// Use a parameterized test fixture
class UffGradientTest : public ::testing::TestWithParam<const char*>
{};

// Parameterized test that works with any molecule file
TEST_P(UffGradientTest, GradientComparison)
{
  const char* filename = GetParam();

  XyzFormat xyz;
  Molecule molecule;

  std::string filepath = std::string(AVOGADRO_DATA) + "/data/xyz/" + filename;
  EXPECT_TRUE(xyz.readFile(filepath, molecule));
  ASSERT_EQ(xyz.error(), std::string());
  ASSERT_GT(molecule.atomCount(), 0);

  UFF uff;
  uff.setMolecule(&molecule);

  // get the positions
  unsigned int n = molecule.atomCount();
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> positions(p, 3 * n);

  Eigen::VectorXd analytical = Eigen::VectorXd::Zero(3 * n);
  Eigen::VectorXd numeric = Eigen::VectorXd::Zero(3 * n);
  uff.gradient(positions, analytical);
  uff.finiteGradient(positions, numeric);

  // assert that the components of each are finite
  for (int i = 0; i < n; ++i) {
    EXPECT_TRUE(std::isfinite(analytical[3 * i]));
    EXPECT_TRUE(std::isfinite(analytical[3 * i + 1]));
    EXPECT_TRUE(std::isfinite(analytical[3 * i + 2]));
    EXPECT_TRUE(std::isfinite(numeric[3 * i]));
    EXPECT_TRUE(std::isfinite(numeric[3 * i + 1]));
    EXPECT_TRUE(std::isfinite(numeric[3 * i + 2]));
  }

  EXPECT_TRUE(checkGradients(analytical, numeric));
}

// Instantiate the test suite with different molecule files
INSTANTIATE_TEST_SUITE_P(
  UffTest, UffGradientTest,
  ::testing::Values("acetylene.xyz", "c2h2f2.xyz", "methane.xyz",
                    "formaldehyde.xyz", "H2O.xyz", "H2S.xyz", "H2Se.xyz",
                    "hooh.xyz", "PF5.xyz", "SF4.xyz", "SF6.xyz", "XeF4.xyz"
                    // Add more molecule files here as needed
                    ));
