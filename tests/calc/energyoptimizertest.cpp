/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/angletools.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <cmath>
#include <limits>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::MaxIndex;
using Avogadro::Real;
using Avogadro::Vector3;

namespace {

// Two carbon atoms, separated along x by `factor` times the LJ minimum
// distance sigma = radiusVDW(C) + radiusVDW(C) (see lennardjones.cpp: the
// pair radius table stores r1 + r2, and the energy is
// depth * ((sigma/r)^2n - 2*(sigma/r)^n), whose minimum is at r == sigma).
Eigen::VectorXd carbonDimerPositions(Real factor)
{
  const Real sigma = 2.0 * Elements::radiusVDW(6);
  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, factor * sigma, 0.0, 0.0;
  return x;
}

Real carbonDimerSigma()
{
  return 2.0 * Elements::radiusVDW(6);
}

Molecule carbonDimerMolecule()
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  return molecule;
}

// A bent, bonded water skeleton (O, H, H) at a distorted starting geometry:
// bonds too long/short and the angle far from tetrahedral/UFF equilibrium.
Molecule waterMolecule()
{
  Molecule molecule;
  auto o = molecule.addAtom(8);
  auto h1 = molecule.addAtom(1);
  auto h2 = molecule.addAtom(1);
  // UFFPrivate's constructor reads atomPositions3d() to bootstrap its VdW
  // pair list, so every atom needs a position set before setMolecule() --
  // see UFFMoleculeWithoutAllAtomPositionsSetDoesNotCrash below for what
  // happens if that is skipped.
  o.setPosition3d(Vector3(0.0, 0.0, 0.0));
  h1.setPosition3d(Vector3(1.0, 0.0, 0.0));
  h2.setPosition3d(Vector3(0.0, 1.0, 0.0));
  molecule.addBond(o, h1, 1);
  molecule.addBond(o, h2, 1);
  return molecule;
}

Eigen::VectorXd distortedWaterPositions()
{
  Eigen::VectorXd x(9);
  // O at origin, H-O-H distorted: long bonds (~1.3 A), obtuse-ish angle.
  x << 0.0, 0.0, 0.0, 1.30, 0.35, 0.0, -1.05, 0.55, 0.0;
  return x;
}

Eigen::VectorXd anotherDistortedWaterPositions()
{
  Eigen::VectorXd x(9);
  // A different, independent distortion: short bonds, different angle.
  x << 0.10, -0.05, 0.02, 0.70, -0.75, 0.05, -0.65, -0.70, -0.05;
  return x;
}

} // namespace

// --- LJ dimer convergence, one test per algorithm ------------------------
//
// The LJ well is stiff (default depth = 100 kJ/mol) so all four algorithms
// should pull a moderately stretched dimer back close to sigma. FIRE-family
// algorithms are not monotone step-to-step, hence "monotone-ish": we only
// check the net energy change and the final gradient/geometry, not that
// every intermediate chunk decreased energy.

TEST(EnergyOptimizerTest, LjDimerLbfgsConvergesNearSigma)
{
  Molecule molecule = carbonDimerMolecule();
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x = carbonDimerPositions(1.6);
  const Real initialEnergy = lj.value(x);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 200;

  ASSERT_TRUE(optimizeSteps(lj, x, options));

  const Real finalEnergy = lj.value(x);
  EXPECT_LT(finalEnergy, initialEnergy);

  Eigen::VectorXd grad(6);
  lj.gradient(x, grad);
  EXPECT_LT(grad.norm(), 1e-3);

  const Real sigma = carbonDimerSigma();
  const Real finalDistance = (x.segment<3>(0) - x.segment<3>(3)).norm();
  EXPECT_NEAR(finalDistance, sigma, 0.05 * sigma);
}

TEST(EnergyOptimizerTest, LjDimerFire2ConvergesNearSigma)
{
  Molecule molecule = carbonDimerMolecule();
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x = carbonDimerPositions(1.6);
  const Real initialEnergy = lj.value(x);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Fire2;
  options.chunkIterations = 3000;

  ASSERT_TRUE(optimizeSteps(lj, x, options));

  const Real finalEnergy = lj.value(x);
  EXPECT_LT(finalEnergy, initialEnergy);

  const Real sigma = carbonDimerSigma();
  const Real finalDistance = (x.segment<3>(0) - x.segment<3>(3)).norm();
  EXPECT_NEAR(finalDistance, sigma, 0.1 * sigma);
}

TEST(EnergyOptimizerTest, LjDimerAbcFireConvergesNearSigma)
{
  Molecule molecule = carbonDimerMolecule();
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x = carbonDimerPositions(1.6);
  const Real initialEnergy = lj.value(x);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::AbcFire;
  options.chunkIterations = 3000;

  ASSERT_TRUE(optimizeSteps(lj, x, options));

  const Real finalEnergy = lj.value(x);
  EXPECT_LT(finalEnergy, initialEnergy);

  const Real sigma = carbonDimerSigma();
  const Real finalDistance = (x.segment<3>(0) - x.segment<3>(3)).norm();
  EXPECT_NEAR(finalDistance, sigma, 0.1 * sigma);
}

TEST(EnergyOptimizerTest, LjDimerHybridConvergesNearSigma)
{
  Molecule molecule = carbonDimerMolecule();
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x = carbonDimerPositions(1.6);
  const Real initialEnergy = lj.value(x);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Hybrid;
  options.chunkIterations = 200;

  OptimizerState state;
  // Several chunks so the Hybrid dispatcher has a chance to hand off from
  // ABC-FIRE to L-BFGS once the gradient falls below the default threshold.
  for (int i = 0; i < 10; ++i)
    ASSERT_TRUE(optimizeSteps(lj, x, options, &state));

  const Real finalEnergy = lj.value(x);
  EXPECT_LT(finalEnergy, initialEnergy);

  const Real sigma = carbonDimerSigma();
  const Real finalDistance = (x.segment<3>(0) - x.segment<3>(3)).norm();
  EXPECT_NEAR(finalDistance, sigma, 0.05 * sigma);
}

// --- UFF water convergence -------------------------------------------------

TEST(EnergyOptimizerTest, UffWaterConvergesToSensibleGeometry)
{
  Molecule molecule = waterMolecule();
  UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd x = distortedWaterPositions();

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 500;

  ASSERT_TRUE(optimizeSteps(uff, x, options));

  Eigen::VectorXd grad(9);
  uff.gradient(x, grad);
  EXPECT_LT(grad.norm(), 1e-2);

  const Real ohDistance1 = (x.segment<3>(0) - x.segment<3>(3)).norm();
  const Real ohDistance2 = (x.segment<3>(0) - x.segment<3>(6)).norm();
  const Real angle =
    Avogadro::calculateAngle(x.segment<3>(3), x.segment<3>(0), x.segment<3>(6));

  // Loose sanity bounds. Fully converged UFF water is O-H 0.990 A and
  // H-O-H 104.51 deg (theta0 for O_3); the window allows for solver
  // differences rather than pinning the digits.
  EXPECT_GT(ohDistance1, 0.9);
  EXPECT_LT(ohDistance1, 1.05);
  EXPECT_GT(ohDistance2, 0.9);
  EXPECT_LT(ohDistance2, 1.05);
  EXPECT_GT(angle, 95.0);
  EXPECT_LT(angle, 115.0);
}

TEST(EnergyOptimizerTest, UffMoleculeWithoutAllAtomPositionsSetDoesNotCrash)
{
  // Regression: UFFPrivate's constructor used to index
  // atomPositions3d()[0] unconditionally to bootstrap its VdW pair list.
  // Core::Molecule allows that array to be shorter than atomCount() (not
  // every atom need have a position set), so an empty array crashed with a
  // libc++-hardening out-of-bounds trap the moment setMolecule() ran, well
  // before any coordinates were ever passed to value()/gradient().
  Molecule molecule;
  molecule.addAtom(8);
  molecule.addAtom(1);
  molecule.addAtom(1);
  molecule.addBond(0, 1, 1);
  molecule.addBond(0, 2, 1);
  // Deliberately do not call setPosition3d()/setAtomPosition3d() on any atom.

  UFF uff;
  EXPECT_NO_THROW(uff.setMolecule(&molecule));

  // The VdW pair list should self-heal once real coordinates arrive.
  Eigen::VectorXd x(9);
  x << 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0;
  const Real energy = uff.value(x);
  EXPECT_TRUE(std::isfinite(energy));
}

// --- Repeated optimizeSteps() calls with the same calculator (#2235) ------

TEST(EnergyOptimizerTest, RepeatedOptimizationWithoutStateBothConverge)
{
  // Regression for #2235: optimizing twice in a row with the same
  // EnergyCalculator instance must not carry stale internal state (e.g.
  // UFF's cached VdW pair list / rebuild counters) into the second run.
  Molecule molecule = waterMolecule();
  UFF uff;
  uff.setMolecule(&molecule);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 500;

  Eigen::VectorXd x1 = distortedWaterPositions();
  ASSERT_TRUE(optimizeSteps(uff, x1, options));
  Eigen::VectorXd grad1(9);
  uff.gradient(x1, grad1);
  EXPECT_LT(grad1.norm(), 1e-2);

  // Second, independent optimization from a different perturbed start, same
  // calculator instance, no persistent OptimizerState.
  Eigen::VectorXd x2 = anotherDistortedWaterPositions();
  ASSERT_TRUE(optimizeSteps(uff, x2, options));
  Eigen::VectorXd grad2(9);
  uff.gradient(x2, grad2);
  EXPECT_LT(grad2.norm(), 1e-2);
}

TEST(EnergyOptimizerTest, RepeatedOptimizationWithPersistentStateBothConverge)
{
  Molecule molecule = waterMolecule();
  UFF uff;
  uff.setMolecule(&molecule);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Fire2;
  options.chunkIterations = 2000;

  OptimizerState state;
  Eigen::VectorXd x1 = distortedWaterPositions();
  ASSERT_TRUE(optimizeSteps(uff, x1, options, &state));
  ASSERT_TRUE(state.initialized);
  Eigen::VectorXd grad1(9);
  uff.gradient(x1, grad1);
  EXPECT_LT(grad1.norm(), 5e-2);

  // Start a fresh optimization: reset the state cleanly (per its documented
  // contract) and drive a new, independent run with the same calculator.
  state = OptimizerState();
  Eigen::VectorXd x2 = anotherDistortedWaterPositions();
  ASSERT_TRUE(optimizeSteps(uff, x2, options, &state));
  Eigen::VectorXd grad2(9);
  uff.gradient(x2, grad2);
  EXPECT_LT(grad2.norm(), 5e-2);
}

// --- Constraints and frozen atoms respected during optimization ----------

TEST(EnergyOptimizerTest, DistanceConstraintHeldDuringOptimization)
{
  Molecule molecule = carbonDimerMolecule();
  LennardJones lj;
  lj.setMolecule(&molecule);

  const Real sigma = carbonDimerSigma();
  const Real constrainedDistance = 1.4 * sigma; // away from the LJ minimum
  lj.setConstraints(
    { Constraint(0, 1, MaxIndex, MaxIndex, constrainedDistance) });

  // Start near the *unconstrained* LJ minimum, not the constraint target, so
  // convergence to the constrained distance is not a coincidence of the
  // starting guess.
  Eigen::VectorXd x = carbonDimerPositions(1.05);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 300;

  ASSERT_TRUE(optimizeSteps(lj, x, options));

  const Real finalDistance = (x.segment<3>(0) - x.segment<3>(3)).norm();
  // Constraint::DefaultDistanceK (41840 kJ/mol/A^2) dominates the LJ well
  // depth (100 kJ/mol), so the restrained distance should win out over the
  // unconstrained sigma minimum.
  EXPECT_NEAR(finalDistance, constrainedDistance, 0.02 * constrainedDistance);
}

TEST(EnergyOptimizerTest, FrozenAtomMaskHoldsAtomFixedDuringOptimization)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);

  LennardJones lj;
  lj.setMolecule(&molecule);

  const Real sigma = 2.0 * Elements::radiusVDW(6);
  Eigen::VectorXd x(9);
  x << 0.0, 0.0, 0.0, 1.6 * sigma, 0.0, 0.0, 0.8 * sigma, 1.6 * sigma, 0.0;
  const Eigen::VectorXd original = x;

  // Freeze the first atom the way real callers do (forcefield.cpp,
  // calcworker.cpp): setMolecule() first, then an explicit setMask() call.
  Eigen::VectorXd mask = Eigen::VectorXd::Ones(9);
  mask.segment<3>(0).setZero();
  lj.setMask(mask);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 300;

  ASSERT_TRUE(optimizeSteps(lj, x, options));

  EXPECT_TRUE(x.segment<3>(0).isApprox(original.segment<3>(0), 1e-12));
  // The unfrozen atoms should actually have moved.
  EXPECT_GT((x.segment<3>(3) - original.segment<3>(3)).norm(), 1e-6);
  EXPECT_GT((x.segment<3>(6) - original.segment<3>(6)).norm(), 1e-6);
}

// --- Zero-atom / one-atom molecules ---------------------------------------

TEST(EnergyOptimizerTest, ZeroAtomMoleculeOptimizesCleanly)
{
  Molecule molecule;
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x(0);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Fire2;
  options.chunkIterations = 5;

  EXPECT_TRUE(optimizeSteps(lj, x, options));
  EXPECT_EQ(x.size(), 0);
}

TEST(EnergyOptimizerTest, ZeroAtomMoleculeOptimizesCleanlyWithLbfgs)
{
  Molecule molecule;
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x(0);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 5;

  EXPECT_TRUE(optimizeSteps(lj, x, options));
  EXPECT_EQ(x.size(), 0);
}

TEST(EnergyOptimizerTest, OneAtomMoleculeOptimizesCleanly)
{
  Molecule molecule;
  molecule.addAtom(6);
  LennardJones lj;
  lj.setMolecule(&molecule);

  Eigen::VectorXd x(3);
  x << 1.0, 2.0, 3.0;
  const Eigen::VectorXd original = x;

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Fire2;
  options.chunkIterations = 5;

  EXPECT_TRUE(optimizeSteps(lj, x, options));
  // No pairwise partner => no force => position should not move.
  EXPECT_TRUE(x.isApprox(original));
  EXPECT_TRUE(x.allFinite());
}

TEST(EnergyOptimizerTest, OneAtomUffMoleculeOptimizesCleanly)
{
  Molecule molecule;
  molecule.addAtom(6);
  UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd x(3);
  x << -1.0, 0.5, 2.0;
  const Eigen::VectorXd original = x;

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 5;

  EXPECT_TRUE(optimizeSteps(uff, x, options));
  EXPECT_TRUE(x.isApprox(original));
  EXPECT_TRUE(x.allFinite());
}

// --- adaptChunkIterations edge cases not already covered ------------------

TEST(AdaptChunkIterationsTest, NanMeasurementIsNoop)
{
  size_t next = adaptChunkIterations(
    7, std::numeric_limits<double>::quiet_NaN(), 33.0, 0.7, 1, 200);
  EXPECT_EQ(next, 7u);
}

TEST(AdaptChunkIterationsTest, NanTargetIsNoop)
{
  size_t next = adaptChunkIterations(
    7, 5.0, std::numeric_limits<double>::quiet_NaN(), 0.7, 1, 200);
  EXPECT_EQ(next, 7u);
}

TEST(AdaptChunkIterationsTest, ZeroTargetIsNoop)
{
  size_t next = adaptChunkIterations(7, 5.0, 0.0, 0.7, 1, 200);
  EXPECT_EQ(next, 7u);
}

TEST(AdaptChunkIterationsTest, NegativeTargetIsNoop)
{
  size_t next = adaptChunkIterations(7, 5.0, -10.0, 0.7, 1, 200);
  EXPECT_EQ(next, 7u);
}
