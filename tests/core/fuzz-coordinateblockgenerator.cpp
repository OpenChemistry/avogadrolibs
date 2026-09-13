/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include "fuzzhelpers.h"

#include <limits>
#include <string>

using namespace Avogadro;
using namespace Avogadro::Core;

namespace {

// Every character the specification understands. Random bytes almost never
// land on these, so bias the generated specs towards them.
const std::string kSpecChars = "#ZLGSNxyzabc01_";

constexpr size_t kMaxSpecLen = 64;
constexpr size_t kMaxAtoms = 64;

// Build a specification string. Most of the time it is made of valid spec
// characters, but sometimes it is raw fuzz data so unhandled characters and
// embedded nulls get exercised too.
std::string consumeSpecification(FuzzedDataProvider& fdp)
{
  if (fdp.ConsumeBool())
    return fdp.ConsumeRandomLengthString(kMaxSpecLen);

  const size_t length = fdp.ConsumeIntegralInRange<size_t>(0, kMaxSpecLen);
  std::string spec;
  spec.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    spec.push_back(
      kSpecChars[fdp.ConsumeIntegralInRange<size_t>(0, kSpecChars.size() - 1)]);
  }
  return spec;
}

// Unlike FuzzHelpers::buildMolecule, atomic numbers span the whole unsigned
// char range: the generator has to cope with custom elements (128-254) and
// InvalidElement as well as the real ones.
Molecule buildMolecule(FuzzedDataProvider& fdp)
{
  Molecule mol;

  const size_t numAtoms = fdp.ConsumeIntegralInRange<size_t>(0, kMaxAtoms);
  for (size_t i = 0; i < numAtoms; ++i)
    mol.addAtom(fdp.ConsumeIntegral<unsigned char>());

  for (size_t i = 0; i < numAtoms; ++i) {
    // Occasionally feed in non-finite coordinates, which a formatter should
    // still be able to print.
    if (fdp.ConsumeBool()) {
      mol.setAtomPosition3d(i, Vector3(std::numeric_limits<Real>::quiet_NaN(),
                                       std::numeric_limits<Real>::infinity(),
                                       -std::numeric_limits<Real>::infinity()));
    } else {
      mol.setAtomPosition3d(i, FuzzHelpers::consumeVector3(fdp));
    }
  }

  // Half the time attach a unit cell so the fractional ('a', 'b', 'c') paths
  // are covered as well as the "no cell" fallback.
  if (fdp.ConsumeBool()) {
    const auto a = fdp.ConsumeFloatingPointInRange<float>(0.0f, 30.0f);
    const auto b = fdp.ConsumeFloatingPointInRange<float>(0.0f, 30.0f);
    const auto c = fdp.ConsumeFloatingPointInRange<float>(0.0f, 30.0f);
    const auto alpha = fdp.ConsumeFloatingPointInRange<float>(0.0f, 180.0f);
    const auto beta = fdp.ConsumeFloatingPointInRange<float>(0.0f, 180.0f);
    const auto gamma = fdp.ConsumeFloatingPointInRange<float>(0.0f, 180.0f);
    mol.setUnitCell(new UnitCell(static_cast<Real>(a), static_cast<Real>(b),
                                 static_cast<Real>(c),
                                 static_cast<Real>(alpha) * DEG_TO_RAD,
                                 static_cast<Real>(beta) * DEG_TO_RAD,
                                 static_cast<Real>(gamma) * DEG_TO_RAD));
  }

  return mol;
}

} // namespace

// Fuzz CoordinateBlockGenerator with arbitrary specifications and molecules.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  const Molecule mol = buildMolecule(fdp);

  CoordinateBlockGenerator generator;
  generator.setMolecule(&mol);
  generator.setSpecification(consumeSpecification(fdp));
  generator.setDistanceUnit(fdp.ConsumeBool()
                              ? CoordinateBlockGenerator::Bohr
                              : CoordinateBlockGenerator::Angstrom);
  generator.generateCoordinateBlock();

  // Re-run with a second specification to exercise the stream reset, and with
  // no molecule at all to cover the early return.
  generator.setSpecification(consumeSpecification(fdp));
  generator.generateCoordinateBlock();

  generator.setMolecule(nullptr);
  generator.generateCoordinateBlock();

  return 0;
}
