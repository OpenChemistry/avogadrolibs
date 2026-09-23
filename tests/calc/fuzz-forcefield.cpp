/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include "fuzzhelpers.h"

#include <cmath>
#include <cstdlib>
#include <limits>

using namespace Avogadro;
using namespace Avogadro::Core;
using namespace Avogadro::Calc;

namespace {

// UFF's setup (angle/OOP/torsion enumeration) is roughly O(N^4) in the worst
// case for a densely-bonded molecule, so keep each fuzz exec cheap by
// capping atom count well below fuzzhelpers.h's own 128-atom ceiling.
constexpr size_t kMaxAtoms = 32;

// Deliberately collapse some atoms onto each other / a line / a plane / a
// cell boundary, so the pairwise and many-body terms regularly see the
// degenerate geometries the ForceFieldEdgeCaseTest suite exercises by hand.
void applyDegenerateGeometry(FuzzedDataProvider& fdp, Molecule& mol)
{
  const Index n = mol.atomCount();
  if (n == 0)
    return;

  const uint8_t choice = fdp.ConsumeIntegral<uint8_t>() % 5;
  Array<Vector3> positions = mol.atomPositions3d();

  switch (choice) {
    case 0: { // snap two atoms onto the same position
      if (n >= 2) {
        Index a = fdp.ConsumeIntegral<uint8_t>() % n;
        Index b = fdp.ConsumeIntegral<uint8_t>() % n;
        positions[b] = positions[a];
      }
      break;
    }
    case 1: { // snap all atoms onto a line (the x axis)
      for (Index i = 0; i < n; ++i)
        positions[i] = Vector3(positions[i].x(), 0.0, 0.0);
      break;
    }
    case 2: { // snap all atoms onto a plane (z = 0)
      for (Index i = 0; i < n; ++i)
        positions[i] = Vector3(positions[i].x(), positions[i].y(), 0.0);
      break;
    }
    case 3: { // snap one atom onto a cell boundary / corner, if there is a
              // cell
      const UnitCell* cell = mol.unitCell();
      if (cell != nullptr && n >= 1) {
        Index a = fdp.ConsumeIntegral<uint8_t>() % n;
        const bool corner = fdp.ConsumeBool();
        positions[a] = corner ? Vector3(0.0, 0.0, 0.0) : cell->aVector();
      }
      break;
    }
    case 4:
    default:
      break; // leave the mindless-molecule geometry alone
  }

  for (Index i = 0; i < n; ++i)
    mol.setAtomPosition3d(i, positions[i]);
}

// Occasionally attach a unit cell, sometimes deliberately degenerate
// (collinear lattice vectors) or extremely skewed/small.
void maybeAttachUnitCell(FuzzedDataProvider& fdp, Molecule& mol)
{
  if (!fdp.ConsumeBool())
    return;

  const uint8_t kind = fdp.ConsumeIntegral<uint8_t>() % 4;
  Vector3 a, b, c;
  switch (kind) {
    case 0: { // ordinary orthorhombic cell
      a = Vector3(fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f), 0, 0);
      b = Vector3(0, fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f), 0);
      c = Vector3(0, 0, fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f));
      break;
    }
    case 1: { // very small cell, smaller than typical bond lengths
      a = Vector3(fdp.ConsumeFloatingPointInRange<float>(0.01f, 0.3f), 0, 0);
      b = Vector3(0, fdp.ConsumeFloatingPointInRange<float>(0.01f, 0.3f), 0);
      c = Vector3(0, 0, fdp.ConsumeFloatingPointInRange<float>(0.01f, 0.3f));
      break;
    }
    case 2: { // highly skewed triclinic cell
      a = Vector3(fdp.ConsumeFloatingPointInRange<float>(3.0f, 20.0f), 0, 0);
      b = Vector3(fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f),
                  fdp.ConsumeFloatingPointInRange<float>(0.1f, 3.0f), 0);
      c = Vector3(fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f),
                  fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f),
                  fdp.ConsumeFloatingPointInRange<float>(0.1f, 3.0f));
      break;
    }
    case 3:
    default: { // degenerate: b parallel to a (zero volume)
      const float scale = fdp.ConsumeFloatingPointInRange<float>(1.0f, 20.0f);
      a = Vector3(scale, 0, 0);
      b = Vector3(2.0f * scale, 0, 0);
      c = Vector3(0, 0, fdp.ConsumeFloatingPointInRange<float>(1.0f, 20.0f));
      break;
    }
  }
  mol.setUnitCell(new UnitCell(a, b, c));
}

// Build the flattened coordinate vector optimizeSteps()/value()/gradient()
// expect, without dereferencing an empty Core::Array.
Eigen::VectorXd flattenPositions(const Molecule& mol)
{
  const Index n = mol.atomCount();
  Eigen::VectorXd x(3 * n);
  if (n == 0)
    return x;
  const Array<Vector3>& positions = mol.atomPositions3d();
  for (Index i = 0; i < n; ++i)
    x.segment<3>(3 * i) = positions[i];
  return x;
}

// Run one calculator through value/gradient/a few optimizer iterations.
// `requireFinite` gates the non-finite-output check. It is false whenever
// NaN/Inf coordinates were fed in (via the caller occasionally corrupting x
// below), or the molecule has a non-regular (zero/near-zero-volume) unit
// cell: Core::UnitCell::computeFractionalMatrix() inverts the cell matrix
// with no regularity check, so a singular cell matrix already makes
// toFractional()/minimumImage() return NaN from perfectly finite atom
// coordinates -- see ForceFieldEdgeCaseTest.
// UnitCellDegenerateCollinearVectorsDoesNotCrash, which documents the same
// carve-out and is why this is not treated as an avogadro/calc bug. In both
// cases only "does not crash or hang" is asserted.
void exerciseCalculator(EnergyCalculator& calc, Molecule& mol,
                        FuzzedDataProvider& fdp, bool requireFinite)
{
  calc.setMolecule(&mol);

  Eigen::VectorXd x = flattenPositions(mol);
  Eigen::VectorXd grad(x.size());
  const Real energy = calc.evaluate(x, &grad);

  if (requireFinite) {
    if (!std::isfinite(energy))
      abort(); // SIGABRT: libFuzzer's default handler catches it; ARM64
               // __builtin_trap()/SIGTRAP is not caught, so a real crash
               // here would otherwise vanish silently.
    for (Eigen::Index i = 0; i < grad.size(); ++i) {
      if (!std::isfinite(grad[i]))
        abort();
    }
  }

  // A handful of optimizer iterations with a fuzz-chosen algorithm. Keep the
  // chunk small; this is about surfacing crashes/NaNs in the optimizer/force
  // field interaction, not converging anything.
  OptimizationOptions options;
  const uint8_t algo = fdp.ConsumeIntegral<uint8_t>() % 4;
  switch (algo) {
    case 0:
      options.algorithm = OptimizationAlgorithm::Lbfgs;
      break;
    case 1:
      options.algorithm = OptimizationAlgorithm::Fire2;
      break;
    case 2:
      options.algorithm = OptimizationAlgorithm::AbcFire;
      break;
    case 3:
    default:
      options.algorithm = OptimizationAlgorithm::Hybrid;
      break;
  }
  options.chunkIterations = 1 + (fdp.ConsumeIntegral<uint8_t>() % 8);

  Eigen::VectorXd optX = x;
  OptimizerState state;
  optimizeSteps(calc, optX, options, &state);

  if (requireFinite) {
    for (Eigen::Index i = 0; i < optX.size(); ++i) {
      if (!std::isfinite(optX[i]))
        abort();
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);
  if (mol.atomCount() > kMaxAtoms)
    return 0; // fuzzhelpers.h's own cap is higher than we want here

  maybeAttachUnitCell(fdp, mol);
  applyDegenerateGeometry(fdp, mol);

  // Occasionally corrupt one coordinate with NaN/Inf -- only the "does not
  // crash or hang" contract applies once that happens.
  bool coordsAreFinite = true;
  if (mol.atomCount() > 0 && fdp.ConsumeIntegralInRange<uint8_t>(0, 9) == 0) {
    Array<Vector3> positions = mol.atomPositions3d();
    const Index a = fdp.ConsumeIntegral<uint8_t>() % mol.atomCount();
    const uint8_t axis = fdp.ConsumeIntegral<uint8_t>() % 3;
    const Real bad = fdp.ConsumeBool() ? std::numeric_limits<Real>::quiet_NaN()
                                       : std::numeric_limits<Real>::infinity();
    Vector3 p = positions[a];
    p[axis] = bad;
    mol.setAtomPosition3d(a, p);
    coordsAreFinite = false;
  }

  // A non-regular (zero/near-zero-volume) cell already makes UnitCell's own
  // fractional-matrix inversion produce NaN/Inf from finite atom
  // coordinates; see the comment on exerciseCalculator().
  const bool cellIsFiniteFriendly =
    mol.unitCell() == nullptr || mol.unitCell()->isRegular();
  const bool requireFinite = coordsAreFinite && cellIsFiniteFriendly;

  LennardJones lj;
  exerciseCalculator(lj, mol, fdp, requireFinite);

  UFF uff;
  exerciseCalculator(uff, mol, fdp, requireFinite);

  return 0;
}
