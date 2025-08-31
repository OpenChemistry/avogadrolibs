/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "qcschema.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;
using std::string;

namespace Avogadro::QuantumIO {

using Core::Array;
using Core::Atom;
using Core::Elements;

QCSchema::QCSchema() {}

QCSchema::~QCSchema() {}

std::vector<std::string> QCSchema::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("qcjson");
  return extensions;
}

std::vector<std::string> QCSchema::mimeTypes() const
{
  return std::vector<std::string>();
}

bool QCSchema::read(std::istream& in, Core::Molecule& molecule)
{
  // This should be JSON so look for key attributes
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

  // check for 'schema_name'
  if (root.find("schema_name") == root.end() ||
      root["schema_name"].get<std::string>() != "QC_JSON") {
    appendError("Error: Input is not a QC_JSON object.");
    return false;
  }

  // get the elements
  if (root.find("symbols") == root.end() || !root["symbols"].is_array()) {
    appendError("Error: no \"symbols\" array found.");
    return false;
  }

  json elements = root["symbols"];
  unsigned char atomicNum(0);
  for (const auto& element : elements) {
    // convert from a string to atomic number
    std::string symbol = element.get<std::string>();
    atomicNum = Elements::atomicNumberFromSymbol(symbol);

    molecule.addAtom(atomicNum);
  }

  // look for geometry for coordinates
  // stored as a numeric array of all coordinates
  // as [atom1x, atom1y, atom1z, atom2x, atom2y, atom2z, ...]
  if (root.find("geometry") == root.end() || !root["geometry"].is_array()) {
    appendError("Error: no \"geometry\" array found.");
    return false;
  }

  json geometry = root["geometry"];
  // check the length of the array
  if (geometry.size() != molecule.atomCount() * 3) {
    appendError("Error: \"geometry\" array has incorrect length.");
    return false;
  }
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    auto a = molecule.atom(i);
    a.setPosition3d(
      Vector3(geometry[3 * i], geometry[3 * i + 1], geometry[3 * i + 2]));
  }

  // check for (optional) connectivity
  bool hasConnectivity = false;
  if (root.find("connectivity") != root.end() &&
      root["connectivity"].is_array()) {
    hasConnectivity = true;

    // read the bonds and orders
    json connectivity = root["connectivity"];
    // stored as an array of 3-value arrays start, end, order
    for (const auto& bond : connectivity) {
      Index start = bond[0].get<Index>() - 1;
      Index end = bond[1].get<Index>() - 1;
      unsigned char order = bond[2].get<unsigned char>();
      molecule.addBond(start, end, order);
    }
  } else {
    // perceive connectivity
    molecule.perceiveBondsSimple();
    molecule.perceiveBondOrders();
  }

  // check for optional comment / name
  if (root.find("comment") != root.end())
    mol.setData("name", root["comment"].get<std::string>());

  // check for molecular_charge and molecular_multiplicity
  if (root.find("molecular_charge") != root.end()) {
    molecule.setData("totalCharge", root["molecular_charge"].get<int>());
  }
  if (root.find("molecular_multiplicity") != root.end()) {
    molecule.setData("totalSpinMultiplicity",
                     root["molecular_multiplicity"].get<int>());
  }

  // if the "properties object exists" look for properties
  if (root.find("properties") != root.end() && root["properties"].is_object()) {
    json properties = root["properties"];

    if (properties.find("dipole_moment") != properties.end()) {
      // read the numeric array
      json dipole = properties["dipole_moment"];
      if (dipole.size() == 3) {
        Core::Variant dipoleMoment(dipole[0], dipole[1], dipole[2]);
        molecule.setData("dipoleMoment", dipoleMoment);
      }
    }

    // todo
    // - partial charges
    // - energies
    // - orbital energies
    // - vibrations
    // - other properties
  }

  return true;
}

} // namespace Avogadro::QuantumIO
