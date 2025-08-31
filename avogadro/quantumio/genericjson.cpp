/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "genericjson.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include "nwchemjson.h"
#include "qcschema.h"

#include <nlohmann/json.hpp>
#include <iostream>

namespace Avogadro::QuantumIO {

using json = nlohmann::json;
using std::string;

GenericJson::GenericJson() {}

GenericJson::~GenericJson() {}

std::vector<std::string> GenericJson::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("json");
  return extensions;
}

std::vector<std::string> GenericJson::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GenericJson::read(std::istream& in, Core::Molecule& molecule)
{
  // this should be JSON so look for key attributes
  FileFormat* reader = nullptr;

  // all of these formats expect a JSON object
  json root;
  try {
    in >> root;
  } catch (json::parse_error& e) {
    appendError("Error parsing JSON: " + string(e.what()));
    return false;
  }

  if (!root.is_object()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  // Okay, look for particular keys
  if (root.find("schema_name") != root.end()) {
    if (root["schema_name"].get<std::string>() == "QC_JSON")
      reader = new QCSchema();
  } else if (root.find("simulation") != root.end()) {
    reader = new NWChemJson();
  }

  // if we didn't find a program name, check for cclib or OpenBabel
  // prefer cclib if it's available
  if (reader == nullptr) {
    // check what other json support is available
    std::vector<const FileFormat*> readers =
      Io::FileFormatManager::instance().fileFormatsFromFileExtension(
        "json", FileFormat::File | FileFormat::Read);

    // loop through readers to check for "cclib" or "Open Babel"
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
    appendError("Could not determine the program used to generate this file.");
    delete reader;
    return false;
  }
}

} // namespace Avogadro::QuantumIO
