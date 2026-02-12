/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/secondarystructure.h>

#include "fuzzhelpers.h"

#include <cstdint>
#include <string>

using namespace Avogadro;
using namespace Avogadro::Core;
using Avogadro::FuzzHelpers::consumeVector3;

constexpr size_t kMaxResidues = 64;
constexpr double kCoordRange = 50.0;

// Build a molecule with residues containing backbone N and O atoms
// at fuzz-driven positions, then run SecondaryStructureAssigner::assign().
// This exercises the hydrogen bond detection, helix/sheet assignment,
// gap plugging, singleton removal, and chain-boundary logic.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol;

  size_t numResidues = fdp.ConsumeIntegralInRange<size_t>(0, kMaxResidues);

  for (size_t r = 0; r < numResidues && fdp.remaining_bytes() > 0; ++r) {
    std::string resName = "ALA";
    Index resNum = static_cast<Index>(r);
    // Use 1-3 chain IDs so we exercise both same-chain and cross-chain paths
    char chain = 'A' + static_cast<char>(fdp.ConsumeIntegral<uint8_t>() % 3);

    Residue& res = mol.addResidue(resName, resNum, chain);

    // Randomly mark some residues as heterogens (skipped by the assigner)
    if (fdp.ConsumeIntegralInRange<uint8_t>(0, 9) == 0)
      res.setHeterogen(true);

    // Add backbone N atom
    if (fdp.ConsumeBool() || true) { // almost always add N
      Atom n = mol.addAtom(7);
      float x =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float y =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float z =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      n.setPosition3d(Vector3(x, y, z));
      res.addResidueAtom("N", n);
    }

    // Add backbone O atom
    if (fdp.ConsumeBool() || true) { // almost always add O
      Atom o = mol.addAtom(8);
      float x =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float y =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float z =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      o.setPosition3d(Vector3(x, y, z));
      res.addResidueAtom("O", o);
    }

    // Optionally add CA (not used by the assigner, but tests tolerance)
    if (fdp.ConsumeBool()) {
      Atom ca = mol.addAtom(6);
      float x =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float y =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      float z =
        fdp.ConsumeFloatingPointInRange<float>(-kCoordRange, kCoordRange);
      ca.setPosition3d(Vector3(x, y, z));
      res.addResidueAtom("CA", ca);
    }
  }

  // Run the secondary structure assignment
  SecondaryStructureAssigner ssa;
  ssa.assign(&mol);

  // Read back all assignments to make sure nothing is corrupt
  for (size_t i = 0; i < mol.residues().size(); ++i) {
    const Residue& res = mol.residue(i);
    (void)res.secondaryStructure();
    (void)res.chainId();
    (void)res.residueName();
  }

  // Run it a second time to exercise re-assignment (clears old hBonds)
  if (fdp.ConsumeBool()) {
    ssa.assign(&mol);
    for (size_t i = 0; i < mol.residues().size(); ++i)
      (void)mol.residue(i).secondaryStructure();
  }

  // Also test construction with a molecule pointer
  {
    SecondaryStructureAssigner ssa2(&mol);
    // Destructor should clean up hBonds even without calling assign()
  }

  return 0;
}
