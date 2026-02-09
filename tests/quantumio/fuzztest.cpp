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

// FUZZ_INPUT_FORMAT is defined in the build system
// e.g., "cjson", "sdf", "xyz", etc.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  std::string input(reinterpret_cast<const char*>(Data), Size);

  // Register quantum file formats
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::GAMESSUSOutput);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::GaussianFchk);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::GaussianCube);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::GenericJson);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::GenericOutput);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::MoldenFile);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::MopacAux);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::NWChemJson);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::NWChemLog);
  Avogadro::Io::FileFormatManager::registerFormat(
    new Avogadro::QuantumIO::ORCAOutput);
  // Avogadro::Io::FileFormatManager::registerFormat(new
  // Avogadro::QuantumIO::QCSchema);

  Molecule molecule;
  FileFormatManager::instance().readString(molecule, input, FUZZ_INPUT_FORMAT);

  return 0;
}
