/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/molecule.h>
#include <avogadro/io/cjsonformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::CjsonFormat;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  std::string input(reinterpret_cast<const char*>(Data), Size);

  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readString(input, molecule);

  return 0;
}
