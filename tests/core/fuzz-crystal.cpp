/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/molecule.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;

// Fuzz crystallographic operations on random crystal structures
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildCrystalMolecule(fdp);
  CrystalTools::wrapAtomsToUnitCell(mol);
  CrystalTools::rotateToStandardOrientation(mol, CrystalTools::TransformAtoms);
  float newVol = fdp.ConsumeFloatingPointInRange<float>(10.0f, 10000.0f);
  CrystalTools::setVolume(mol, static_cast<Real>(newVol),
                          CrystalTools::TransformAtoms);
  CrystalTools::niggliReduce(mol, CrystalTools::TransformAtoms);
  CrystalTools::isNiggliReduced(mol);
  // Supercell capped at 3x3x3 to avoid blowup
  unsigned int sa = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  unsigned int sb = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  unsigned int sc = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
  CrystalTools::buildSupercell(mol, sa, sb, sc);
  Array<Vector3> frac;
  CrystalTools::fractionalCoordinates(mol, frac);

  return 0;
}
