/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "genericoutput.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/io/xyzformat.h>

#include "gamessus.h"
#include "molden.h"
#include "nwchemlog.h"
#include "orca.h"

#include <iostream>

namespace Avogadro::QuantumIO {

GenericOutput::GenericOutput() {}

GenericOutput::~GenericOutput() {}

std::vector<std::string> GenericOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("out");
  extensions.emplace_back("output");
  extensions.emplace_back("log");
  return extensions;
}

std::vector<std::string> GenericOutput::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GenericOutput::read(std::istream& in, Core::Molecule& molecule)
{
  // check the stream line-by-line until we see the program name
  FileFormat* reader = nullptr;

  std::string line;
  while (std::getline(in, line)) {
    if (line.find("Northwest Computational Chemistry Package") !=
        std::string::npos) {
      // NWChem
      reader = new NWChemLog;
      break;
    } else if (line.find("GAMESS VERSION") != std::string::npos) {
      // GAMESS-US .. don't know if we can read Firefly or GAMESS-UK
      reader = new GAMESSUSOutput;
      break;
    } else if (line.find("[Molden Format]") != std::string::npos) {
      // molden with .out extension
      reader = new MoldenFile;
      break;
    } else if (line.find("O   R   C   A") != std::string::npos) {
      // ORCA reader
      reader = new ORCAOutput;
      break;
    } else if (line.find("xtb:") != std::string::npos) {
      // xtb reader
      reader = new Io::XyzFormat;
      break;
    }
  }

  // if we didn't find a program name, check for cclib or OpenBabel
  // prefer cclib if it's available
  if (reader == nullptr) {
    // check what output is available
    std::vector<const FileFormat*> readers =
      Io::FileFormatManager::instance().fileFormatsFromFileExtension(
        "out", FileFormat::File | FileFormat::Read);

    // loop through writers to check for "cclib" or "Open Babel"
    for (const FileFormat* r : readers) {
      if (r->name() == "cclib") {
        reader = r->newInstance();
        break;
      } else if (r->identifier().compare(0, 9, "OpenBabel") == 0) {
        reader = r->newInstance();
        break;
      }
    }
  }

  // rewind the stream
  in.seekg(0, std::ios::beg);
  in.clear();

  if (reader) {
    bool success = reader->readFile(fileName(), molecule);
    delete reader;
    return success;
  } else {
    appendError(
      "Could not determine the program used to generate this output file.");
    delete reader;
    return false;
  }
}

} // namespace Avogadro::QuantumIO
