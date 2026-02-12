/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>

#include "fuzzhelpers.h"

#include <cstdint>
#include <string>

using namespace Avogadro;
using namespace Avogadro::Core;
using Avogadro::FuzzHelpers::consumeAtomicNumber;
using Avogadro::FuzzHelpers::consumeVector3;

constexpr size_t kMaxSteps = 128;
constexpr size_t kMaxAtoms = 64;
constexpr size_t kMaxResidues = 32;
constexpr size_t kMaxNameLen = 8;

// Common PDB backbone atom names exercised for name lookups
static const char* kBackboneNames[] = { "N", "CA", "C", "O", "CB", "H" };
constexpr size_t kNumBackboneNames = 6;

// Known residue names so resolveResidueBonds hits the dictionary
static const char* kKnownResidues[] = {
  "ALA", "GLY", "VAL", "LEU", "ILE", "PRO", "PHE", "TRP", "MET", "SER", "THR",
  "CYS", "TYR", "HIS", "ASP", "GLU", "ASN", "GLN", "LYS", "ARG", "UNK"
};
constexpr size_t kNumKnownResidues = 21;

// Fuzz Residue with random mutation sequences, atom name lookups,
// bond resolution, copy/assign, color, and secondary structure.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol;

  // Build some residues with backbone atoms
  size_t numResidues = fdp.ConsumeIntegralInRange<size_t>(0, kMaxResidues);

  for (size_t r = 0; r < numResidues && fdp.remaining_bytes() > 0; ++r) {
    // Pick residue name: sometimes known, sometimes random
    std::string resName;
    if (fdp.ConsumeBool()) {
      resName =
        kKnownResidues[fdp.ConsumeIntegral<uint8_t>() % kNumKnownResidues];
    } else {
      resName = fdp.ConsumeRandomLengthString(kMaxNameLen);
    }
    Index resNum = static_cast<Index>(r);
    // Chain IDs: A-D so we get some same-chain and cross-chain patterns
    char chain = 'A' + static_cast<char>(fdp.ConsumeIntegral<uint8_t>() % 4);

    Residue& res = mol.addResidue(resName, resNum, chain);

    if (fdp.ConsumeBool())
      res.setHeterogen(true);

    // Add some atoms with backbone-like names
    size_t numAtoms = fdp.ConsumeIntegralInRange<size_t>(0, kNumBackboneNames);
    for (size_t a = 0; a < numAtoms && mol.atomCount() < kMaxAtoms; ++a) {
      unsigned char z = consumeAtomicNumber(fdp);
      Atom atom = mol.addAtom(z);
      atom.setPosition3d(consumeVector3(fdp));

      // Use a backbone name or a fuzz-generated name
      std::string atomName;
      if (fdp.ConsumeBool()) {
        atomName =
          kBackboneNames[fdp.ConsumeIntegral<uint8_t>() % kNumBackboneNames];
      } else {
        atomName = fdp.ConsumeRandomLengthString(kMaxNameLen);
      }
      res.addResidueAtom(atomName, atom);
    }

    // Set secondary structure to a random valid enum
    int ss = fdp.ConsumeIntegralInRange<int>(-3, 7);
    res.setSecondaryStructure(static_cast<Residue::SecondaryStructure>(ss));

    // Set color
    if (fdp.ConsumeBool()) {
      uint8_t cr = fdp.ConsumeIntegral<uint8_t>();
      uint8_t cg = fdp.ConsumeIntegral<uint8_t>();
      uint8_t cb = fdp.ConsumeIntegral<uint8_t>();
      res.setColor(Vector3ub(cr, cg, cb));
    }
  }

  // Now run random operations on the residues
  size_t steps = fdp.ConsumeIntegralInRange<size_t>(0, kMaxSteps);
  size_t resCount = mol.residues().size();

  for (size_t s = 0; s < steps && fdp.remaining_bytes() > 0 && resCount > 0;
       ++s) {
    size_t ri = fdp.ConsumeIntegral<uint8_t>() % resCount;
    Residue& res = mol.residue(ri);

    switch (fdp.ConsumeIntegral<uint8_t>() % 10) {
      case 0: { // atomByName with known name
        std::string name =
          kBackboneNames[fdp.ConsumeIntegral<uint8_t>() % kNumBackboneNames];
        Atom a = res.atomByName(name);
        (void)a.isValid();
        break;
      }
      case 1: { // atomByName with random name
        std::string name = fdp.ConsumeRandomLengthString(kMaxNameLen);
        Atom a = res.atomByName(name);
        (void)a.isValid();
        break;
      }
      case 2: { // residueAtoms
        auto atoms = res.residueAtoms();
        (void)atoms.size();
        break;
      }
      case 3: { // hasAtomByIndex
        Index idx = fdp.ConsumeIntegral<uint8_t>();
        (void)res.hasAtomByIndex(idx);
        break;
      }
      case 4: { // atomName by Index
        Index idx = fdp.ConsumeIntegral<uint8_t>();
        (void)res.atomName(idx);
        break;
      }
      case 5: { // atomicNumber by name
        std::string name =
          kBackboneNames[fdp.ConsumeIntegral<uint8_t>() % kNumBackboneNames];
        (void)res.atomicNumber(name);
        break;
      }
      case 6: { // resolveResidueBonds
        res.resolveResidueBonds(mol);
        break;
      }
      case 7: { // color
        (void)res.color();
        break;
      }
      case 8: { // copy constructor
        Residue copy(res);
        (void)copy.residueName();
        (void)copy.residueId();
        (void)copy.chainId();
        (void)copy.secondaryStructure();
        (void)copy.isHeterogen();
        (void)copy.color();
        break;
      }
      case 9: { // assignment
        if (resCount > 1) {
          size_t other = fdp.ConsumeIntegral<uint8_t>() % resCount;
          Residue copy = mol.residue(other);
          (void)copy.residueName();
        }
        break;
      }
      default:
        break;
    }
  }

  // Read back all residue properties
  for (size_t i = 0; i < resCount; ++i) {
    const Residue& res = mol.residue(i);
    (void)res.residueName();
    (void)res.residueId();
    (void)res.chainId();
    (void)res.secondaryStructure();
    (void)res.isHeterogen();
    (void)res.color();
    (void)res.residueAtoms();
  }

  return 0;
}
