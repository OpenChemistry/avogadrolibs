/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/uff.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/constraint.h>
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
  ASSERT_TRUE(analytical.allFinite());
  ASSERT_TRUE(numeric.allFinite());

  // check numeric to analytic gradient for all atoms in a molecule
  for (int i = 0; i < 3 * n; i++) {
    // are these components within 10% of each other?
    EXPECT_NEAR(analytical[i], numeric[i],
                std::max(2.5e-5, 0.1 * std::fabs(analytical[i])));
  }
}

TEST_P(UffGradientTest, EvaluateMatchesValueAndGradient)
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

  const unsigned int n = molecule.atomCount();
  Core::Array<Vector3> pos = molecule.atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> positions(p, 3 * n);

  const Real expectedEnergy = uff.value(positions);
  Eigen::VectorXd expectedGradient = Eigen::VectorXd::Zero(3 * n);
  uff.gradient(positions, expectedGradient);

  Eigen::VectorXd fusedGradient(1); // intentional wrong size to validate resize
  const Real fusedEnergy = uff.evaluate(positions, &fusedGradient);

  EXPECT_NEAR(fusedEnergy, expectedEnergy,
              std::max(1e-8, 1e-10 * std::fabs(expectedEnergy)));
  ASSERT_EQ(fusedGradient.size(), expectedGradient.size());
  for (int i = 0; i < expectedGradient.size(); ++i) {
    EXPECT_NEAR(fusedGradient[i], expectedGradient[i],
                std::max(1e-7, 1e-8 * std::fabs(expectedGradient[i])));
  }
}

// Instantiate the test suite with different molecule files
INSTANTIATE_TEST_SUITE_P(
  UffTest, UffGradientTest,
  ::testing::Values("acetylene.xyz", "c2h2f2.xyz", "methane.xyz",
                    "formaldehyde.xyz", "H2O.xyz", "H2S.xyz", "H2Se.xyz",
                    "hooh.xyz", "PF5.xyz", "SF4.xyz", "SF6.xyz", "XeF4.xyz"
                    // Add more molecule files here as needed
                    ));

// Restraints are documented in kJ/mol (core/constraint.h), the same units as
// the UFF energy, so adding one must raise the energy by exactly k * delta^2
// and the gradient by the restraint's own gradient.
TEST(UffConstraintTest, RestraintEnergyAndGradientAreInKilojoules)
{
  Molecule molecule;
  Atom o = molecule.addAtom(8);
  Atom h1 = molecule.addAtom(1);
  Atom h2 = molecule.addAtom(1);
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(1.0, 0.1, 0.0));
  h2.setPosition3d(Vector3(-0.2, 0.95, 0.05));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);

  Eigen::VectorXd x(9);
  for (Index i = 0; i < 3; ++i)
    x.segment<3>(3 * i) = molecule.atomPosition3d(i);

  UFF uff;
  uff.setMolecule(&molecule);
  Eigen::VectorXd grad0;
  const Real e0 = uff.evaluate(x, &grad0);

  // O-H1 distance restraint 0.1 A shorter than the current bond
  const Vector3 oh = x.segment<3>(3) - x.segment<3>(0);
  const Real distance = oh.norm();
  const Real distanceDelta = 0.1;
  const Real distanceK = 50.0; // kJ/mol/A^2
  Constraint bond(0, 1, MaxIndex, MaxIndex, distance - distanceDelta);
  bond.setK(distanceK);

  // H1-O-H2 angle restraint 5 degrees smaller than the current angle
  const Vector3 oh2 = x.segment<3>(6) - x.segment<3>(0);
  const Real angle = std::acos(oh.dot(oh2) / (oh.norm() * oh2.norm()));
  const Real angleDelta = 5.0 * DEG_TO_RAD_D;
  const Real angleK = 20.0; // kJ/mol/rad^2
  Constraint bend(1, 0, 2, MaxIndex, (angle - angleDelta) / DEG_TO_RAD_D);
  bend.setK(angleK);

  uff.setConstraints({ bond, bend });
  Eigen::VectorXd grad1;
  const Real e1 = uff.evaluate(x, &grad1);

  const Real expected = distanceK * distanceDelta * distanceDelta +
                        angleK * angleDelta * angleDelta;
  EXPECT_NEAR(e1 - e0, expected, 1e-9);
  EXPECT_NEAR(uff.value(x) - e0, expected, 1e-9);

  // the distance restraint alone pulls H1 toward O by 2 k delta
  uff.setConstraints({ bond });
  Eigen::VectorXd grad2;
  uff.evaluate(x, &grad2);
  const Vector3 expectedH1 = 2.0 * distanceK * distanceDelta * oh / distance;
  for (int i = 0; i < 3; ++i) {
    EXPECT_NEAR(grad2[3 + i] - grad0[3 + i], expectedH1[i], 1e-9);
    EXPECT_NEAR(grad2[i] - grad0[i], -expectedH1[i], 1e-9);
  }
}

namespace {
Molecule bentWater()
{
  Molecule molecule;
  Atom o = molecule.addAtom(8);
  Atom h1 = molecule.addAtom(1);
  Atom h2 = molecule.addAtom(1);
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(1.2, 0.1, 0.0));
  h2.setPosition3d(Vector3(-0.2, 1.1, 0.05));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);
  return molecule;
}

Eigen::VectorXd positionsOf(const Molecule& molecule)
{
  Eigen::VectorXd x(3 * molecule.atomCount());
  for (Index i = 0; i < molecule.atomCount(); ++i)
    x.segment<3>(3 * i) = molecule.atomPosition3d(i);
  return x;
}
} // namespace

// Same contract as LennardJonesTest.SetMoleculeUsesFrozenAtomMask
TEST(UffMaskTest, SetMoleculeUsesFrozenAtomMask)
{
  Molecule molecule = bentWater();
  molecule.setFrozenAtom(0, true);

  UFF uff;
  uff.setMolecule(&molecule);

  const Eigen::VectorXd mask = uff.mask();
  ASSERT_EQ(mask.rows(), 9);
  EXPECT_TRUE(mask.head<3>().isZero());
  EXPECT_TRUE(mask.tail<6>().isOnes());

  // the frozen atom feels no force
  Eigen::VectorXd grad;
  uff.gradient(positionsOf(molecule), grad);
  EXPECT_TRUE(grad.head<3>().isZero());
  EXPECT_FALSE(grad.tail<6>().isZero());
}

TEST(UffMaskTest, SetMoleculeWithoutFrozenAtomsFreesEveryAtom)
{
  Molecule molecule = bentWater();

  UFF uff;
  uff.setMolecule(&molecule);

  const Eigen::VectorXd mask = uff.mask();
  ASSERT_EQ(mask.rows(), 9);
  EXPECT_TRUE(mask.isOnes());
}

TEST(UffMaskTest, SetMaskAfterSetMoleculeOverridesAndSetMoleculeResets)
{
  Molecule molecule = bentWater();
  UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd mask = Eigen::VectorXd::Ones(9);
  mask.segment<3>(3).setZero(); // freeze H1
  uff.setMask(mask);
  Eigen::VectorXd grad;
  uff.gradient(positionsOf(molecule), grad);
  EXPECT_TRUE(grad.segment<3>(3).isZero());

  // a new setMolecule() starts again from the molecule's frozen atoms
  uff.setMolecule(&molecule);
  EXPECT_TRUE(uff.mask().isOnes());
}

TEST(UffMaskTest, SingleAtomMoleculeGetsMaskOfTheRightSize)
{
  Molecule molecule;
  molecule.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  UFF uff;
  uff.setMolecule(&molecule);
  EXPECT_EQ(uff.mask().rows(), 3);
}
