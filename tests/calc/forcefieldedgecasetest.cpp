/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <cmath>
#include <limits>
#include <memory>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using Avogadro::Real;
using Avogadro::Vector3;

namespace {

enum class CalculatorKind
{
  LJ,
  UFF
};

std::unique_ptr<EnergyCalculator> makeCalculator(CalculatorKind kind)
{
  switch (kind) {
    case CalculatorKind::LJ:
      return std::make_unique<LennardJones>();
    case CalculatorKind::UFF:
      return std::make_unique<UFF>();
  }
  return nullptr;
}

void expectAllFinite(const Eigen::VectorXd& v, const char* what)
{
  for (Eigen::Index i = 0; i < v.size(); ++i)
    EXPECT_TRUE(std::isfinite(v[i]))
      << what << " component " << i << " is not finite: " << v[i];
}

// Central finite-difference gradient, independent of
// EnergyCalculator::finiteGradient(), for cross-checking analytic gradients
// on smooth geometries.
Eigen::VectorXd centralDifferenceGradient(EnergyCalculator& calc,
                                          const Eigen::VectorXd& x,
                                          Real h = 1e-6)
{
  Eigen::VectorXd grad = Eigen::VectorXd::Zero(x.size());
  for (Eigen::Index i = 0; i < x.size(); ++i) {
    Eigen::VectorXd xp = x;
    Eigen::VectorXd xm = x;
    xp[i] += h;
    xm[i] -= h;
    grad[i] = (calc.value(xp) - calc.value(xm)) / (2.0 * h);
  }
  return grad;
}

} // namespace

class ForceFieldEdgeCaseTest : public ::testing::TestWithParam<CalculatorKind>
{};

static std::string calculatorKindName(
  const ::testing::TestParamInfo<CalculatorKind>& info)
{
  return info.param == CalculatorKind::LJ ? "LJ" : "UFF";
}

// --- Overlapping atoms ------------------------------------------------

TEST_P(ForceFieldEdgeCaseTest, TwoAtomsExactlyCoincidentBonded)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x = Eigen::VectorXd::Zero(6); // both atoms at the origin
  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, TwoAtomsExactlyCoincidentNonBonded)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(8);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x = Eigen::VectorXd::Zero(6);
  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, ThreeAtomsExactlyCoincident)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x = Eigen::VectorXd::Zero(9);
  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- Linear molecules (collinear angle/dihedral terms are a documented,
// removable-singularity case in gradients.h -- the analytic gradient
// short-circuits to 0 there rather than solving the ill-posed direction, so
// we only assert finiteness/no-crash for these, not a finite-difference
// match). ---------------------------------------------------------------

TEST_P(ForceFieldEdgeCaseTest, LinearCO2)
{
  Molecule molecule;
  molecule.addAtom(8);
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addBond(0, 1, 2);
  molecule.addBond(1, 2, 2);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(9);
  x << -1.16, 0.0, 0.0, 0.0, 0.0, 0.0, 1.16, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, LinearAcetylene)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(1);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 3);
  molecule.addBond(2, 3, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(12);
  x << -2.19, 0.0, 0.0, -1.10, 0.0, 0.0, 1.10, 0.0, 0.0, 2.19, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(12);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, LinearFourAtomChainUndefinedDihedral)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);
  molecule.addBond(2, 3, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(12);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0, 3.0, 0.0, 0.0, 4.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(12);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- Planar molecules (sp2 centers with an exactly-zero out-of-plane
// angle); smooth away from the singular collinear/degenerate cases above,
// so these are checked against a finite-difference gradient too. ---------

TEST_P(ForceFieldEdgeCaseTest, PlanarFormaldehydeZeroOutOfPlane)
{
  Molecule molecule;
  auto c = molecule.addAtom(6);
  auto o = molecule.addAtom(8);
  auto h1 = molecule.addAtom(1);
  auto h2 = molecule.addAtom(1);
  molecule.addBond(c, o, 2);
  molecule.addBond(c, h1, 1);
  molecule.addBond(c, h2, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  // All atoms in the z=0 plane: C at the origin, O along +y, the two H atoms
  // symmetric about the y-axis. The C center has exactly 3 neighbors and 0
  // out-of-plane (Wilson) angle.
  const Real h121 = 121.0 * Avogadro::PI / 180.0;
  Eigen::VectorXd x(12);
  x << 0.0, 0.0, 0.0,                                   // C
    0.0, 1.20, 0.0,                                     // O
    1.10 * std::sin(h121), 1.10 * std::cos(h121), 0.0,  // H1
    -1.10 * std::sin(h121), 1.10 * std::cos(h121), 0.0; // H2

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd analytic(12);
  calc->gradient(x, analytic);
  expectAllFinite(analytic, "gradient");

  const Eigen::VectorXd numeric = centralDifferenceGradient(*calc, x);
  for (Eigen::Index i = 0; i < x.size(); ++i) {
    EXPECT_NEAR(analytic[i], numeric[i],
                std::max(1e-3, 0.05 * std::fabs(analytic[i])));
  }
}

TEST_P(ForceFieldEdgeCaseTest, PlanarEthyleneZeroOutOfPlane)
{
  Molecule molecule;
  auto c1 = molecule.addAtom(6);
  auto c2 = molecule.addAtom(6);
  auto h1a = molecule.addAtom(1);
  auto h1b = molecule.addAtom(1);
  auto h2a = molecule.addAtom(1);
  auto h2b = molecule.addAtom(1);
  molecule.addBond(c1, c2, 2);
  molecule.addBond(c1, h1a, 1);
  molecule.addBond(c1, h1b, 1);
  molecule.addBond(c2, h2a, 1);
  molecule.addBond(c2, h2b, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  // All 6 atoms in the z=0 plane (D2h ethylene). Every sp2 carbon has 0
  // out-of-plane angle.
  const Real hAngle = 121.7 * Avogadro::PI / 180.0;
  const Real cc = 0.67;
  const Real ch = 1.09;
  Eigen::VectorXd x(18);
  x << -cc, 0.0, 0.0,                                         // C1
    cc, 0.0, 0.0,                                             // C2
    -cc + ch * std::cos(hAngle), ch * std::sin(hAngle), 0.0,  // H1a
    -cc + ch * std::cos(hAngle), -ch * std::sin(hAngle), 0.0, // H1b
    cc - ch * std::cos(hAngle), ch * std::sin(hAngle), 0.0,   // H2a
    cc - ch * std::cos(hAngle), -ch * std::sin(hAngle), 0.0;  // H2b

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd analytic(18);
  calc->gradient(x, analytic);
  expectAllFinite(analytic, "gradient");

  const Eigen::VectorXd numeric = centralDifferenceGradient(*calc, x);
  for (Eigen::Index i = 0; i < x.size(); ++i) {
    EXPECT_NEAR(analytic[i], numeric[i],
                std::max(1e-3, 0.05 * std::fabs(analytic[i])));
  }
}

// --- Angles at 0 and 180 degrees ----------------------------------------

TEST_P(ForceFieldEdgeCaseTest, AngleExactlyZeroDegrees)
{
  // Two bonded neighbors (atoms 0 and 2) sit at the same position, so the
  // angle 0-1-2 is exactly 0 degrees.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(9);
  x << 1.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, AngleExactly180Degrees)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(9);
  x << -1.5, 0.0, 0.0, 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, AngleVertexCoincidesWithNeighbor)
{
  // The most degenerate angle case: the central atom (1) sits exactly on
  // top of one of its bonded neighbors (0), so that arm has zero length.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(9);
  x << 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy))
    << "UFF angleEvaluate() must guard r1/r2 == 0 before acos(dot/(r1*r2))";

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- Unit cells -----------------------------------------------------------

TEST_P(ForceFieldEdgeCaseTest, UnitCellAtomsOnBoundary)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setUnitCell(new UnitCell(
    Vector3(5.0, 0.0, 0.0), Vector3(0.0, 5.0, 0.0), Vector3(0.0, 0.0, 5.0)));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 4.999, 0.0, 0.0; // just inside the far boundary

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, UnitCellPeriodicImageZeroMinimumDistance)
{
  // Atom 1 sits one full lattice translation away from atom 0: the minimum
  // image distance between them is exactly 0.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setUnitCell(new UnitCell(
    Vector3(5.0, 0.0, 0.0), Vector3(0.0, 5.0, 0.0), Vector3(0.0, 0.0, 5.0)));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.5, 0.5, 0.5, 5.5, 0.5, 0.5; // atom 1 = atom 0 + one full a-vector

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, UnitCellSmallerThanBondLength)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.setUnitCell(new UnitCell(
    Vector3(0.5, 0.0, 0.0), Vector3(0.0, 0.5, 0.0), Vector3(0.0, 0.0, 0.5)));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0; // bond spans several cell images

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, UnitCellHighlySkewedTriclinic)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  // A strongly skewed (but still non-degenerate) triclinic cell.
  molecule.setUnitCell(new UnitCell(
    Vector3(6.0, 0.0, 0.0), Vector3(5.7, 1.2, 0.0), Vector3(5.5, 0.8, 1.0)));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.2, 0.1, 0.0, 3.0, 0.5, 0.3;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, UnitCellDegenerateCollinearVectorsDoesNotCrash)
{
  // A zero-volume cell (b is parallel to a) makes UnitCell's fractional
  // matrix singular (Core::UnitCell::computeFractionalMatrix() inverts the
  // cell matrix with no regularity check -- out of scope for avogadro/calc
  // to fix). The only contract here is "does not crash or hang"; the energy
  // may legitimately come back non-finite, so it is deliberately not
  // asserted.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setUnitCell(new UnitCell(Vector3(5.0, 0.0, 0.0),
                                    Vector3(10.0, 0.0, 0.0), // parallel to a
                                    Vector3(0.0, 0.0, 5.0)));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 2.0, 0.0, 0.0;

  EXPECT_NO_THROW({
    const Real energy = calc->value(x);
    (void)energy;
    Eigen::VectorXd grad(6);
    calc->gradient(x, grad);
  });
}

// --- Unsupported elements --------------------------------------------------

TEST_P(ForceFieldEdgeCaseTest, ElementFarBeyondAnyParameterTable)
{
  // Atomic number 200 has no entry in either calculator's parameter table
  // (LennardJones falls back to Elements::radiusVDW()'s default; UFF has no
  // matching uffparams row at all). Neither should crash or produce NaN --
  // UFF's contract is to simply refuse the whole molecule (see the guard
  // added to UFFPrivate::UFFPrivate() in uff.cpp).
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(static_cast<unsigned char>(200));
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, ElementJustBeyondUffTable)
{
  // UFF's own parameter table stops at element 102; LJ supports the full
  // periodic table.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(static_cast<unsigned char>(103));
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, DummyElementZero)
{
  // Element 0 ("Du") has a real uffparams row (it is UFF's own dummy-atom
  // type), so this exercises the "supported edge of the table" rather than
  // the unsupported-element path.
  Molecule molecule;
  molecule.addAtom(0);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- No bonds / unusual bond orders ---------------------------------------

TEST_P(ForceFieldEdgeCaseTest, AtomsWithNoBonds)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addAtom(1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(9);
  x << 0.0, 0.0, 0.0, 3.0, 0.5, 0.0, -2.0, 1.0, 0.5;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(9);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, BondOrderZero)
{
  // A bond order of 0 previously drove UFF's log(order) bond-order
  // correction to log(0) == -inf, poisoning r0/kb with NaN (see the clamp
  // added in UFFPrivate::calculateRij() in uff.cpp).
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 0);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy))
    << "bond order 0 must not reach log(0) unguarded";

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, BondOrderUnusuallyLarge)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, static_cast<unsigned char>(250));

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.5, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- NaN / Inf coordinates: only "does not crash or hang" is asserted ----

TEST_P(ForceFieldEdgeCaseTest, NanCoordinateDoesNotCrash)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, std::numeric_limits<Real>::quiet_NaN(), 0.0, 0.0;

  EXPECT_NO_THROW({
    const Real energy = calc->value(x);
    (void)energy; // may legitimately be NaN -- not asserted
    Eigen::VectorXd grad(6);
    calc->gradient(x, grad);
  });
}

TEST_P(ForceFieldEdgeCaseTest, InfCoordinateDoesNotCrash)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, std::numeric_limits<Real>::infinity(), 0.0, 0.0;

  EXPECT_NO_THROW({
    const Real energy = calc->value(x);
    (void)energy;
    Eigen::VectorXd grad(6);
    calc->gradient(x, grad);
  });
}

// --- Huge and very small separations --------------------------------------

TEST_P(ForceFieldEdgeCaseTest, HugeSeparation)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.0e6, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

TEST_P(ForceFieldEdgeCaseTest, VerySmallSeparation)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1);

  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(6);
  x << 0.0, 0.0, 0.0, 1.0e-8, 0.0, 0.0;

  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(6);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

// --- Empty / trivial molecules ---------------------------------------------

TEST_P(ForceFieldEdgeCaseTest, EmptyMolecule)
{
  Molecule molecule;
  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(0);
  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(0);
  calc->gradient(x, grad);
  EXPECT_EQ(grad.size(), 0);
}

TEST_P(ForceFieldEdgeCaseTest, SingleAtom)
{
  Molecule molecule;
  molecule.addAtom(6);
  auto calc = makeCalculator(GetParam());
  calc->setMolecule(&molecule);

  Eigen::VectorXd x(3);
  x << 1.0, -2.0, 0.5;
  const Real energy = calc->value(x);
  EXPECT_TRUE(std::isfinite(energy));

  Eigen::VectorXd grad(3);
  calc->gradient(x, grad);
  expectAllFinite(grad, "gradient");
}

INSTANTIATE_TEST_SUITE_P(LjAndUff, ForceFieldEdgeCaseTest,
                         ::testing::Values(CalculatorKind::LJ,
                                           CalculatorKind::UFF),
                         calculatorKindName);
