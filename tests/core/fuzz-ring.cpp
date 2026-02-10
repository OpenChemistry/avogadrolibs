/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/ringperceiver.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;

// Fuzz SSSR ring detection on random molecular graphs
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);
  RingPerceiver perceiver(&mol);
  perceiver.rings();

  return 0;
}
