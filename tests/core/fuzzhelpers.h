/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_FUZZ_HELPERS_H
#define AVOGADRO_FUZZ_HELPERS_H

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <algorithm>
#include <cmath>
#include <string>

namespace Avogadro::FuzzHelpers {

// Caps to prevent OOM/timeout during fuzzing
constexpr size_t kMaxAtoms = 128;
constexpr size_t kMaxBonds = 128;
constexpr double kCoordRange = 100.0; // angstroms

/**
 * Build a "mindless molecule" from fuzz data.
 *
 * Consumes from FuzzedDataProvider:
 *   1 byte:  numAtoms (clamped to kMaxAtoms)
 *   numAtoms bytes: atomic numbers mapped to [1, 118]
 *   numAtoms * 3 floats: x, y, z in [-kCoordRange, kCoordRange]
 *   1 byte:  numBonds (clamped to kMaxBonds)
 *   numBonds * 3 bytes: (atom1, atom2, order) with index mod numAtoms
 */
inline Core::Molecule buildMolecule(FuzzedDataProvider& fdp)
{
  Core::Molecule mol;

  uint8_t rawNumAtoms = fdp.ConsumeIntegral<uint8_t>();
  size_t numAtoms = std::min(static_cast<size_t>(rawNumAtoms), kMaxAtoms);
  if (numAtoms == 0)
    return mol;

  // Add atoms with atomic numbers in [1, 118]
  for (size_t i = 0; i < numAtoms; ++i) {
    uint8_t z = fdp.ConsumeIntegral<uint8_t>();
    z = static_cast<uint8_t>(1 + (z % (Core::element_count - 1)));
    mol.addAtom(z);
  }

  // Set 3D positions
  for (size_t i = 0; i < numAtoms; ++i) {
    float x = fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
    float y = fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
    float z = fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
    mol.setAtomPosition3d(i, Vector3(x, y, z));
  }

  // Add explicit bonds
  uint8_t rawNumBonds = fdp.ConsumeIntegral<uint8_t>();
  size_t numBonds = std::min(static_cast<size_t>(rawNumBonds), kMaxBonds);
  for (size_t i = 0; i < numBonds; ++i) {
    uint8_t a = fdp.ConsumeIntegral<uint8_t>();
    uint8_t b = fdp.ConsumeIntegral<uint8_t>();
    uint8_t order = fdp.ConsumeIntegral<uint8_t>();
    size_t ia = static_cast<size_t>(a) % numAtoms;
    size_t ib = static_cast<size_t>(b) % numAtoms;
    if (ia == ib)
      continue;
    mol.addBond(ia, ib, static_cast<unsigned char>(1 + (order % 3)));
  }

  return mol;
}

/**
 * Build a molecule with a UnitCell attached (for crystal tests).
 * After building a normal molecule, consumes 6 floats for cell parameters.
 */
inline Core::Molecule buildCrystalMolecule(FuzzedDataProvider& fdp)
{
  Core::Molecule mol = buildMolecule(fdp);

  float a = fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f);
  float b = fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f);
  float c = fdp.ConsumeFloatingPointInRange<float>(1.0f, 30.0f);
  // Angles in degrees, converted to radians
  float alpha = fdp.ConsumeFloatingPointInRange<float>(30.0f, 150.0f);
  float beta = fdp.ConsumeFloatingPointInRange<float>(30.0f, 150.0f);
  float gamma = fdp.ConsumeFloatingPointInRange<float>(30.0f, 150.0f);

  auto* cell = new Core::UnitCell(
    static_cast<Real>(a), static_cast<Real>(b), static_cast<Real>(c),
    static_cast<Real>(alpha) * DEG_TO_RAD, static_cast<Real>(beta) * DEG_TO_RAD,
    static_cast<Real>(gamma) * DEG_TO_RAD);
  mol.setUnitCell(cell);
  return mol;
}

/**
 * Consume a random-length string from remaining fuzz data.
 */
inline std::string consumeString(FuzzedDataProvider& fdp, size_t maxLen = 4096)
{
  return fdp.ConsumeRandomLengthString(maxLen);
}

unsigned char consumeAtomicNumber(FuzzedDataProvider& fdp)
{
  uint8_t z = fdp.ConsumeIntegral<uint8_t>();
  return static_cast<unsigned char>(1 + (z % (Core::element_count - 1)));
}

Vector3 consumeVector3(FuzzedDataProvider& fdp)
{
  float x = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  float y = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  float z = fdp.ConsumeFloatingPointInRange<float>(-FuzzHelpers::kCoordRange,
                                                   FuzzHelpers::kCoordRange);
  return Vector3(x, y, z);
}

} // namespace Avogadro::FuzzHelpers

#endif // AVOGADRO_FUZZ_HELPERS_H
