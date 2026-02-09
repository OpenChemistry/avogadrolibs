/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/molecule.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;

// Fuzz bond perception on random atom clouds
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);
  mol.clearBonds();
  double tolerance = fdp.ConsumeFloatingPointInRange<double>(0.0, 2.0);
  double minDist = fdp.ConsumeFloatingPointInRange<double>(0.0, 1.0);
  mol.perceiveBondsSimple(tolerance, minDist);
  mol.perceiveBondOrders();
  mol.perceiveSubstitutedCations();

  return 0;
}
