/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/molecule.h>
#include <avogadro/core/neighborperceiver.h>

#include "fuzzhelpers.h"

using namespace Avogadro;
using namespace Avogadro::Core;

// Fuzz spatial neighbor indexing and queries
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Molecule mol = FuzzHelpers::buildMolecule(fdp);
  const auto& positions = mol.atomPositions3d();
  if (positions.empty())
    return 0;

  float maxDist = fdp.ConsumeFloatingPointInRange<float>(0.1f, 10.0f);
  NeighborPerceiver np(positions, maxDist);
  uint8_t numQueries = fdp.ConsumeIntegralInRange<uint8_t>(0, 16);
  for (uint8_t i = 0; i < numQueries; ++i) {
    float qx = fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f);
    float qy = fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f);
    float qz = fdp.ConsumeFloatingPointInRange<float>(-20.0f, 20.0f);
    np.getNeighborsInclusive(Vector3(qx, qy, qz));
  }

  return 0;
}
