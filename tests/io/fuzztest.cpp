/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormatManager;

// FUZZ_INPUT_FORMAT is defined in the build system
// e.g., "cjson", "sdf", "xyz", etc.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  std::string input(reinterpret_cast<const char*>(Data), Size);

  Molecule molecule;
  FileFormatManager::instance().readString(molecule, input, FUZZ_INPUT_FORMAT);

  return 0;
}
