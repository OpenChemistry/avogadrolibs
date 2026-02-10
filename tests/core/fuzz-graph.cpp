/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/graph.h>

using Avogadro::Core::Graph;

// Fuzz graph add/remove vertex/edge sequences
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  Graph g;
  uint8_t numVerts = fdp.ConsumeIntegral<uint8_t>();
  size_t nv = std::min(static_cast<size_t>(numVerts), size_t(128));
  for (size_t i = 0; i < nv; ++i)
    g.addVertex();

  uint8_t numEdges = fdp.ConsumeIntegral<uint8_t>();
  size_t ne = std::min(static_cast<size_t>(numEdges), size_t(256));
  for (size_t i = 0; i < ne; ++i) {
    uint8_t a = fdp.ConsumeIntegral<uint8_t>();
    uint8_t b = fdp.ConsumeIntegral<uint8_t>();
    if (nv == 0)
      continue;
    size_t ia = a % nv, ib = b % nv;
    if (ia != ib)
      g.addEdge(ia, ib);
  }

  g.connectedComponents();
  g.subgraphsCount();

  // Random vertex removals
  uint8_t numRemove = fdp.ConsumeIntegral<uint8_t>();
  size_t nr = std::min(static_cast<size_t>(numRemove), g.size());
  for (size_t i = 0; i < nr && g.size() > 0; ++i)
    g.removeVertex(fdp.ConsumeIntegral<uint8_t>() % g.size());
  g.connectedComponents();

  return 0;
}
