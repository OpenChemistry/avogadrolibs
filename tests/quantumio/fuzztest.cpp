/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

// register potential formats to fuzz
#include <avogadro/quantumio/gamessus.h>
#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>
#include <avogadro/quantumio/genericjson.h>
#include <avogadro/quantumio/genericoutput.h>
#include <avogadro/quantumio/molden.h>
#include <avogadro/quantumio/mopacaux.h>
#include <avogadro/quantumio/nwchemjson.h>
#include <avogadro/quantumio/nwchemlog.h>
#include <avogadro/quantumio/orca.h>
#include <avogadro/quantumio/qcschema.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormatManager;

namespace {

// Register the quantum file formats exactly once. Re-registering on every
// iteration leaks each rejected format object and exhausts memory in seconds.
bool registerFormats()
{
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::GAMESSUSOutput);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::GaussianFchk);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::GaussianCube);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::GenericJson);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::GenericOutput);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::MoldenFile);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::MopacAux);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::NWChemJson);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::NWChemLog);
  FileFormatManager::registerFormat(new Avogadro::QuantumIO::ORCAOutput);
  // Avogadro::Io::FileFormatManager::registerFormat(new
  // Avogadro::QuantumIO::QCSchema);
  return true;
}

} // namespace

// FUZZ_INPUT_FORMAT is defined in the build system
// e.g., "cjson", "sdf", "xyz", etc.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  static const bool registered = registerFormats();
  (void)registered;

  std::string input(reinterpret_cast<const char*>(Data), Size);

  Molecule molecule;
  FileFormatManager::instance().readString(molecule, input, FUZZ_INPUT_FORMAT);

  return 0;
}
