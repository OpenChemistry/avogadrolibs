/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <fuzzer/FuzzedDataProvider.h>

#include <avogadro/core/utilities.h>

#include "fuzzhelpers.h"

using namespace Avogadro::Core;
using namespace Avogadro::FuzzHelpers;

// Fuzz string parsing and conversion utilities
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  FuzzedDataProvider fdp(Data, Size);

  std::string input = consumeString(fdp);
  split(input, ' ');
  split(input, ',', false);
  split(input, '\n');
  trimmed(input);
  lexicalCast<int>(input);
  lexicalCast<double>(input);
  lexicalCast<float>(input);
  contains(input, "test");
  contains(input, "TEST", false);
  startsWith(input, "begin");
  endsWith(input, "end");

  return 0;
}
