/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/angletools.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <cmath>
#include <limits>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::Index;
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

// A bonded n-alkane (C_n H_{2n+2}) on a zigzag backbone, with every atom
// displaced by a fixed pseudo-random offset (no RNG state: the offsets are a
// pure function of the coordinate index). Big enough that L-BFGS needs
// hundreds of iterations, so a chunked run exercises the stopping criteria.
Molecule perturbedAlkane(size_t nCarbons, Eigen::VectorXd& positions,
                         Real extraOffset = 0.0)
{
  Molecule molecule;
  std::vector<Vector3> pos;
  std::vector<Index> carbons;
  for (size_t i = 0; i < nCarbons; ++i) {
    carbons.push_back(molecule.addAtom(6).index());
    pos.emplace_back(1.25 * static_cast<Real>(i), (i % 2) ? 0.4 : 0.0, 0.0);
    if (i > 0)
      molecule.addBond(carbons[i - 1], carbons[i], 1);
  }
  const Real side = (nCarbons > 0) ? 1.0 : 0.0;
  for (size_t i = 0; i < nCarbons; ++i) {
    const Real up = (i % 2) ? 1.0 : -1.0;
    const size_t nH = (i == 0 || i + 1 == nCarbons) ? 3 : 2;
    for (size_t h = 0; h < nH; ++h) {
      const Real dz = (h == 0) ? 0.9 : -0.9;
      Vector3 p = pos[i] + Vector3(h == 2 ? -0.6 * side : 0.0, 0.5 * up,
                                   h == 2 ? 0.0 : dz);
      Index a = molecule.addAtom(1).index();
      pos.push_back(p);
      molecule.addBond(carbons[i], a, 1);
    }
  }
  positions.resize(3 * static_cast<Eigen::Index>(pos.size()));
  for (size_t i = 0; i < pos.size(); ++i) {
    for (size_t k = 0; k < 3; ++k) {
      const Real offset =
        std::sin(12.9898 * static_cast<Real>(3 * i + k) + 1.0);
      // extraOffset moves the start by a tiny, fixed pattern, to reach other
      // trajectories from the same geometry.
      const Real tweak =
        extraOffset * std::sin(7.1 * static_cast<Real>(3 * i + k) + 0.3);
      positions[3 * static_cast<Eigen::Index>(i) + k] =
        pos[i][k] + 0.1 * offset + tweak;
    }
    molecule.setAtomPosition3d(i, positions.segment<3>(3 * i));
  }
  return molecule;
}

// Analytic objective that counts evaluations. Rosenbrock in n dimensions is
// non-quadratic and curved, so L-BFGS builds up genuine history on it.
// `quantum` > 0 rounds the energy to a multiple of `quantum` (the gradient
// stays exact), which imitates an energy model whose noise floor sits above
// what the line search is trying to resolve.
class CountingFunction : public EnergyCalculator
{
public:
  explicit CountingFunction(Real quantum = 0.0) : m_quantum(quantum) {}

  EnergyCalculator* newInstance() const override
  {
    return new CountingFunction(m_quantum);
  }
  std::string identifier() const override { return "CountingFunction"; }
  std::string name() const override { return "CountingFunction"; }
  std::string description() const override { return "Test objective"; }
  Molecule::ElementMask elements() const override
  {
    return Molecule::ElementMask();
  }

  void setMolecule(Molecule*) override {}

  Real value(const Eigen::VectorXd& x) override
  {
    Real f = 0.0;
    for (Eigen::Index i = 0; i + 1 < x.size(); ++i) {
      const Real a = x[i + 1] - x[i] * x[i];
      const Real b = 1.0 - x[i];
      f += 100.0 * a * a + b * b;
    }
    if (m_quantum > 0.0)
      f = m_quantum * std::round(f / m_quantum);
    return f;
  }

  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override
  {
    grad.setZero(x.size());
    for (Eigen::Index i = 0; i + 1 < x.size(); ++i) {
      const Real a = x[i + 1] - x[i] * x[i];
      grad[i] += -400.0 * a * x[i] - 2.0 * (1.0 - x[i]);
      grad[i + 1] += 200.0 * a;
    }
  }

  Real evaluate(const Eigen::VectorXd& x, Eigen::VectorXd* grad) override
  {
    ++evaluations;
    return EnergyCalculator::evaluate(x, grad);
  }

  size_t evaluations = 0;

private:
  Real m_quantum;
};

Eigen::VectorXd rosenbrockStart(Eigen::Index n)
{
  Eigen::VectorXd x(n);
  for (Eigen::Index i = 0; i < n; ++i)
    x[i] = (i % 2) ? 1.2 : -1.2;
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

// --- chunked L-BFGS must keep going until the caller says stop ------------
//
// Regression: DefaultStoppingSolverProgress enables a relative past-delta
// test (cppoptlib 2.0) that ended every chunk after ~4 iterations near a
// minimum, discarding the L-BFGS memory, so the GUI loop never converged.

TEST(EnergyOptimizerTest, ChunkedLbfgsConvergesGradientBelowTolerance)
{
  Eigen::VectorXd x;
  Molecule molecule = perturbedAlkane(10, x);
  ASSERT_EQ(molecule.atomCount(), 32u);
  UFF uff;
  uff.setMolecule(&molecule);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 50;

  OptimizerState state;
  Eigen::VectorXd grad(x.size());
  Real gInf = std::numeric_limits<Real>::infinity();
  const int maxChunks = 400; // 20000 requested iterations
  for (int chunk = 0; chunk < maxChunks; ++chunk) {
    ASSERT_TRUE(optimizeSteps(uff, x, options, &state));
    uff.gradient(x, grad);
    gInf = grad.cwiseAbs().maxCoeff();
    if (gInf < 1e-4)
      break;
  }
  EXPECT_LT(gInf, 1e-4);
}

TEST(EnergyOptimizerTest, LbfgsChunkRunsRequestedIterationsNearMinimum)
{
  Eigen::VectorXd x;
  Molecule molecule = perturbedAlkane(10, x);
  UFF uff;
  uff.setMolecule(&molecule);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 20;
  OptimizerState state;
  // Get close to the minimum (but not onto it).
  for (int i = 0; i < 4; ++i)
    ASSERT_TRUE(optimizeSteps(uff, x, options, &state));

  Eigen::VectorXd grad(x.size());
  uff.gradient(x, grad);
  const Real gBefore = grad.cwiseAbs().maxCoeff();
  ASSERT_GT(gBefore, 1e-2) << "already converged; test would prove nothing";

  // A single long chunk must keep iterating (not stop after a few steps on
  // a tiny energy change) and so converge.
  options.chunkIterations = 1000;
  ASSERT_TRUE(optimizeSteps(uff, x, options, &state));
  uff.gradient(x, grad);
  EXPECT_LT(grad.cwiseAbs().maxCoeff(), 1e-4);
}

// --- L-BFGS history persists across chunks ---------------------------------
//
// Running K chunks of one iteration with a persistent OptimizerState must be
// the same computation as one chunk of K iterations: same iterates, same
// number of energy/gradient evaluations. Before the correction pairs were
// kept in OptimizerState every chunk restarted from steepest descent.

TEST(EnergyOptimizerTest, LbfgsOneIterationChunksMatchOneLongChunk)
{
  const int iterations = 25;
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;

  CountingFunction single;
  Eigen::VectorXd xSingle = rosenbrockStart(10);
  options.chunkIterations = iterations;
  OptimizerState singleState;
  ASSERT_TRUE(optimizeSteps(single, xSingle, options, &singleState));
  EXPECT_EQ(singleState.iterationsRun, static_cast<size_t>(iterations));

  CountingFunction chunked;
  Eigen::VectorXd xChunked = rosenbrockStart(10);
  options.chunkIterations = 1;
  OptimizerState chunkedState;
  for (int i = 0; i < iterations; ++i) {
    ASSERT_TRUE(optimizeSteps(chunked, xChunked, options, &chunkedState));
    EXPECT_EQ(chunkedState.iterationsRun, 1u);
  }

  EXPECT_EQ(chunked.evaluations, single.evaluations);
  EXPECT_EQ(xChunked, xSingle);
  EXPECT_EQ(chunkedState.energy, singleState.energy);
  EXPECT_EQ(chunkedState.lbfgsCount, singleState.lbfgsCount);
  EXPECT_EQ(chunkedState.lbfgsPos, singleState.lbfgsPos);
  EXPECT_GT(chunkedState.lbfgsCount, 1u);
  // The run must have used history (and wrapped the ring buffer), or the
  // comparison above proves nothing.
  EXPECT_EQ(chunkedState.lbfgsCount, 10u);
}

TEST(EnergyOptimizerTest, LbfgsWithoutStateRestartsEveryChunk)
{
  // Control for the test above: stateless chunks lose the history, so they do
  // not reproduce the long chunk. (Guards against the equivalence test
  // passing only because the problem never needs history.)
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;

  CountingFunction single;
  Eigen::VectorXd xSingle = rosenbrockStart(10);
  options.chunkIterations = 25;
  ASSERT_TRUE(optimizeSteps(single, xSingle, options));

  CountingFunction stateless;
  Eigen::VectorXd xStateless = rosenbrockStart(10);
  options.chunkIterations = 1;
  for (int i = 0; i < 25; ++i)
    ASSERT_TRUE(optimizeSteps(stateless, xStateless, options));
  EXPECT_NE(xStateless, xSingle);
}

TEST(EnergyOptimizerTest, LbfgsHistoryDroppedOnSizeChange)
{
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 5;

  CountingFunction f;
  OptimizerState state;
  Eigen::VectorXd x10 = rosenbrockStart(10);
  ASSERT_TRUE(optimizeSteps(f, x10, options, &state));
  ASSERT_GT(state.lbfgsCount, 0u);
  ASSERT_EQ(state.lbfgsS.rows(), 10);

  // A different problem size through the same state: the old pairs must not
  // be fed to the solver. The result has to equal a fresh run on x6.
  Eigen::VectorXd x6 = rosenbrockStart(6);
  Eigen::VectorXd x6Fresh = x6;
  ASSERT_TRUE(optimizeSteps(f, x6, options, &state));
  EXPECT_EQ(state.lbfgsS.rows(), 6);
  CountingFunction g;
  ASSERT_TRUE(optimizeSteps(g, x6Fresh, options));
  EXPECT_EQ(x6, x6Fresh);
}

TEST(EnergyOptimizerTest, FireChunkClearsLbfgsHistory)
{
  CountingFunction f;
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(10);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 5;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  ASSERT_GT(state.lbfgsCount, 0u);

  options.algorithm = OptimizationAlgorithm::AbcFire;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.lbfgsCount, 0u);
  EXPECT_EQ(state.lbfgsS.size(), 0);
  EXPECT_EQ(state.lbfgsY.size(), 0);
  EXPECT_EQ(state.iterationsRun, 5u);
  EXPECT_EQ(state.stopReason, OptimizerStopReason::IterationLimit);

  // Back to L-BFGS: starts a new history rather than reusing a stale one.
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 1;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.lbfgsCount, 1u);
}

TEST(EnergyOptimizerTest, FireHandlesDimensionNotMultipleOfThree)
{
  // The per-atom move cap walks xyz triplets; a trailing partial triplet
  // must be skipped, not read past the end of the step vector (caught by
  // the sanitizer jobs, and by Eigen's bounds assert in a debug build).
  for (Eigen::Index n : { 4, 10 }) {
    CountingFunction f;
    Eigen::VectorXd x = rosenbrockStart(n);
    OptimizationOptions options;
    options.algorithm = OptimizationAlgorithm::AbcFire;
    options.chunkIterations = 5;
    ASSERT_GT(options.fire.maxMove, 0.0);
    ASSERT_TRUE(optimizeSteps(f, x, options));
    EXPECT_TRUE(x.allFinite());
  }
}

TEST(EnergyOptimizerTest, ClearLbfgsHistoryResetsFields)
{
  CountingFunction f;
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(10);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 4;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  ASSERT_GT(state.lbfgsCount, 0u);
  state.clearLbfgsHistory();
  EXPECT_EQ(state.lbfgsCount, 0u);
  EXPECT_EQ(state.lbfgsS.size(), 0);
  EXPECT_EQ(state.lbfgsScaling, 1.0);
}

// --- L-BFGS reports iterations run and stalls --------------------------------

TEST(EnergyOptimizerTest, LbfgsReportsIterationLimit)
{
  CountingFunction f;
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(10);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 7;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.iterationsRun, 7u);
  EXPECT_EQ(state.stopReason, OptimizerStopReason::IterationLimit);
}

TEST(EnergyOptimizerTest, LbfgsStopsWhenEnergyNoiseStallsLineSearch)
{
  // Energy quantized to 1e-6: once the true energy is within a few quanta of
  // the minimum the line search cannot find a decrease and every iteration
  // burns its full evaluation budget. The chunk has to end as stalled after
  // a few such iterations instead of running all 500.
  CountingFunction f(1e-6);
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 500;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.stopReason, OptimizerStopReason::Stalled);
  EXPECT_LT(state.iterationsRun, 500u);
  EXPECT_LT(f.evaluations, 2000u);
}

TEST(EnergyOptimizerTest, LbfgsStallIsIndependentOfChunkSize)
{
  // The stall test needs three consecutive bad iterations. Chunks of one
  // iteration must reach the same verdict as one long chunk: same stopping
  // iteration, same evaluation count, bitwise-equal positions.
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;

  CountingFunction single(1e-6);
  Eigen::VectorXd xSingle = rosenbrockStart(4);
  options.chunkIterations = 500;
  OptimizerState singleState;
  ASSERT_TRUE(optimizeSteps(single, xSingle, options, &singleState));
  ASSERT_EQ(singleState.stopReason, OptimizerStopReason::Stalled);
  ASSERT_LT(singleState.iterationsRun, 500u);

  for (size_t chunk : { size_t(1), size_t(2), size_t(7) }) {
    CountingFunction chunked(1e-6);
    Eigen::VectorXd xChunked = rosenbrockStart(4);
    options.chunkIterations = chunk;
    OptimizerState chunkedState;
    size_t total = 0;
    while (total < 500) {
      ASSERT_TRUE(optimizeSteps(chunked, xChunked, options, &chunkedState));
      total += chunkedState.iterationsRun;
      if (chunkedState.stopReason == OptimizerStopReason::Stalled)
        break;
    }
    EXPECT_EQ(chunkedState.stopReason, OptimizerStopReason::Stalled)
      << "chunk " << chunk;
    EXPECT_EQ(total, singleState.iterationsRun) << "chunk " << chunk;
    EXPECT_EQ(chunked.evaluations, single.evaluations) << "chunk " << chunk;
    EXPECT_EQ(chunkedState.lbfgsRestarts, singleState.lbfgsRestarts)
      << "chunk " << chunk;
    EXPECT_EQ(xChunked, xSingle) << "chunk " << chunk;
  }
}

TEST(EnergyOptimizerTest, ClearLbfgsHistoryResetsStallCounters)
{
  OptimizerState state;
  state.stallXViolations = 2;
  state.stallFViolations = 1;
  state.clearLbfgsHistory();
  EXPECT_EQ(state.stallXViolations, 0);
  EXPECT_EQ(state.stallFViolations, 0);
}

// --- L-BFGS restarts from steepest descent once on a stall -----------------
//
// A history whose H_0 scaling is absurdly large (1e30) stands in for stale
// correction pairs: the first direction is huge, the line search cannot find
// an acceptable step in its evaluation budget and the iteration makes no
// progress. Started from steepest descent the same problem converges.

namespace {
struct RestartRun
{
  size_t iterations = 0;
  size_t evaluations = 0;
  size_t restarts = 0;
  OptimizerStopReason reason = OptimizerStopReason::IterationLimit;
  double energy = 0.0;
  Eigen::VectorXd x;
};

// Build some history, poison its scaling, then run up to `budget` iterations
// in chunks of `chunk` (stopping at the first Stalled report).
RestartRun runPoisoned(size_t chunk, size_t budget, Real quantum = 0.0)
{
  CountingFunction f(quantum);
  OptimizerState state;
  RestartRun run;
  run.x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 6;
  optimizeSteps(f, run.x, options, &state);
  state.lbfgsScaling = 1e30;
  const size_t evalsBefore = f.evaluations;
  options.chunkIterations = chunk;
  while (run.iterations < budget) {
    options.chunkIterations = std::min(chunk, budget - run.iterations);
    if (!optimizeSteps(f, run.x, options, &state))
      break;
    run.iterations += state.iterationsRun;
    run.reason = state.stopReason;
    if (state.stopReason == OptimizerStopReason::Stalled)
      break;
  }
  run.evaluations = f.evaluations - evalsBefore;
  run.restarts = state.lbfgsRestarts;
  run.energy = state.energy;
  return run;
}
} // namespace

TEST(EnergyOptimizerTest, LbfgsRestartRecoversFromStaleHistory)
{
  // Stops at the minimum's noise floor, far below the E = 3.16 where the
  // poisoned history stalls the line search.
  const RestartRun run = runPoisoned(200, 200);
  EXPECT_GE(run.restarts, 1u);
  EXPECT_LT(run.energy, 1e-8);
}

TEST(EnergyOptimizerTest, LbfgsRestartIsIndependentOfChunkSize)
{
  const RestartRun single = runPoisoned(200, 200);
  ASSERT_GE(single.restarts, 1u);
  for (size_t chunk : { size_t(1), size_t(2), size_t(3), size_t(7) }) {
    const RestartRun chunked = runPoisoned(chunk, 200);
    EXPECT_EQ(chunked.iterations, single.iterations) << "chunk " << chunk;
    EXPECT_EQ(chunked.evaluations, single.evaluations) << "chunk " << chunk;
    EXPECT_EQ(chunked.restarts, single.restarts) << "chunk " << chunk;
    EXPECT_EQ(chunked.reason, single.reason) << "chunk " << chunk;
    EXPECT_EQ(chunked.x, single.x) << "chunk " << chunk;
  }
}

TEST(EnergyOptimizerTest, LbfgsStallAfterRestartIsReported)
{
  // On the quantized problem steepest descent has no more luck than L-BFGS
  // did: one restart is spent, the second stall is reported.
  CountingFunction f(1e-6);
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 500;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.stopReason, OptimizerStopReason::Stalled);
  EXPECT_GE(state.lbfgsRestarts, 1u);
  // Reporting the stall also clears the restart flag (see
  // LbfgsStalledStateStartsFresh).
  EXPECT_FALSE(state.lbfgsRestartSpent);
}

TEST(EnergyOptimizerTest, LbfgsStalledStateStartsFresh)
{
  // A stall leaves nothing behind that could end the next call on its first
  // iteration: no history, no violation counters, no spent restart. Without
  // this, a caller that keeps calling after a stall (the Python loops do)
  // was stuck for good once the counters had reached three.
  CountingFunction f(1e-6);
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 500;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  ASSERT_EQ(state.stopReason, OptimizerStopReason::Stalled);
  EXPECT_EQ(state.lbfgsCount, 0u);
  EXPECT_EQ(state.stallXViolations, 0);
  EXPECT_EQ(state.stallFViolations, 0);
  EXPECT_FALSE(state.lbfgsRestartSpent);
  // The cached energy / gradient stay valid for the positions returned.
  EXPECT_EQ(state.gradient.size(), x.size());
  EXPECT_TRUE(std::isfinite(state.energy));
}

TEST(EnergyOptimizerTest, LbfgsStallWithoutHistoryLeavesNoCounters)
{
  CountingFunction f(1e9);
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 50;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  ASSERT_EQ(state.stopReason, OptimizerStopReason::Stalled);
  EXPECT_EQ(state.stallXViolations, 0);
  EXPECT_EQ(state.stallFViolations, 0);
}

TEST(EnergyOptimizerTest, ChunkedLbfgsRecoversAfterStallOnStiffStart)
{
  // Regression: from this start (a 1e-9 tweak of the usual one) the line
  // search crawls in steps below 1e-10 Angstrom at E ~ 264, |g| ~ 170 and
  // the run is reported as stalled. The loop keeps calling, as the GUI and
  // the Python bindings do, and has to get out again.
  Eigen::VectorXd x;
  Molecule molecule = perturbedAlkane(4, x, 1e-9);
  UFF uff;
  uff.setMolecule(&molecule);

  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 50;

  OptimizerState state;
  Eigen::VectorXd grad(x.size());
  Real gInf = std::numeric_limits<Real>::infinity();
  for (int chunk = 0; chunk < 400; ++chunk) {
    ASSERT_TRUE(optimizeSteps(uff, x, options, &state));
    uff.gradient(x, grad);
    gInf = grad.cwiseAbs().maxCoeff();
    if (gInf < 1e-4)
      break;
  }
  EXPECT_LT(gInf, 1e-4);
}

TEST(EnergyOptimizerTest, LbfgsStallWithoutHistoryIsNotRestarted)
{
  // A flat energy (quantum far above the values) with a non-zero gradient:
  // no curvature pair is ever accepted, so there is no history to discard.
  CountingFunction f(1e9);
  OptimizerState state;
  Eigen::VectorXd x = rosenbrockStart(4);
  OptimizationOptions options;
  options.algorithm = OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 50;
  ASSERT_TRUE(optimizeSteps(f, x, options, &state));
  EXPECT_EQ(state.stopReason, OptimizerStopReason::Stalled);
  EXPECT_EQ(state.lbfgsRestarts, 0u);
  EXPECT_LT(state.iterationsRun, 50u);
}

TEST(EnergyOptimizerTest, ClearLbfgsHistoryResetsRestartFlag)
{
  OptimizerState state;
  state.lbfgsRestartSpent = true;
  state.lbfgsRestarts = 3;
  state.clearLbfgsHistory();
  EXPECT_FALSE(state.lbfgsRestartSpent);
  EXPECT_EQ(state.lbfgsRestarts, 3u); // cumulative count is kept
}
