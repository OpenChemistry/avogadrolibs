/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "cjsonformat.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <jsoncpp.cpp>

namespace Avogadro {
namespace Io {

using std::string;

using Core::Elements;
using Core::Atom;
using Core::Bond;
using Core::Variant;

CjsonFormat::CjsonFormat()
{
  setSupportedOperations(ReadWrite | File | Stream | String);
}

CjsonFormat::~CjsonFormat()
{
}

bool CjsonFormat::read(std::istream &file, Core::Molecule &molecule)
{
  Json::Value root;
  Json::Reader reader;
  bool ok = reader.parse(file, root);
  if (!ok) {
    appendError("Error parsing JSON: " + reader.getFormatedErrorMessages());
    return false;
  }

  Json::Value value = root["chemical json"];
  if (value.empty()) {
    appendError("Error: no \"chemical json\" key found.");
    return false;
  }

  // It looks like a valid Chemical JSON file - attempt to read data.
  value = root["name"];
  if (!value.empty() && value.isString())
    molecule.setData("name", value.asString());
  value = root["inchi"];
  if (!value.empty() && value.isString())
    molecule.setData("inchi", value.asString());

  // Read in the atomic data.
  Json::Value atoms = root["atoms"];
  if (atoms.empty()) {
    appendError("Error: no \"atom\" key found");
    return false;
  }
  else if (atoms.type() != Json::objectValue) {
    appendError("Error: \"atom\" is not of type object");
    return false;
  }

  value =  atoms["elements"];
  if (value.empty()) {
    appendError("Error: no \"atoms.elements\" key found");
    return false;
  }
  else if (value.type() != Json::objectValue) {
    appendError("Error: \"atoms.elements\" is not of type object");
    return false;
  }

  value = value["number"];
  if (value.empty()) {
    appendError("Error: no \"atoms.elements.number\" key found");
    return false;
  }

  size_t atomCount(0);
  if (value.isArray()) {
    atomCount = static_cast<size_t>(value.size());
    for (unsigned int i = 0; i < atomCount; ++i)
      molecule.addAtom(static_cast<unsigned char>(value.get(i, 0).asInt()));
  }
  else {
    appendError("Error: \"atoms.elements.number\" is not of type array");
    return false;
  }

  Json::Value coords = atoms["coords"];
  if (!coords.empty()) {
    value = coords["3d"];
    if (value.isArray()) {
      if (value.size() && atomCount != static_cast<size_t>(value.size() / 3)) {
        appendError("Error: number of elements != number of 3D coordinates.");
        return false;
      }
      for (unsigned int i = 0; i < atomCount; ++i) {
        Atom a = molecule.atom(i);
        a.setPosition3d(Vector3(value.get(3 * i + 0, 0).asDouble(),
                                value.get(3 * i + 1, 0).asDouble(),
                                value.get(3 * i + 2, 0).asDouble()));
      }
    }

    value = coords["2d"];
    if (value.isArray()) {
      if (value.size() && atomCount != static_cast<size_t>(value.size() / 2)) {
        appendError("Error: number of elements != number of 2D coordinates.");
        return false;
      }
      for (unsigned int i = 0; i < atomCount; ++i) {
        Atom a = molecule.atom(i);
        a.setPosition2d(Vector2(value.get(2 * i + 0, 0).asDouble(),
                                value.get(2 * i + 1, 0).asDouble()));
      }
    }
  }

  // Now for the bonding data.
  Json::Value bonds = root["bonds"];
  if (!bonds.empty()) {
    value = bonds["connections"];
    if (value.empty()) {
      appendError("Error: no \"bonds.connections\" key found");
      return false;
    }

    value = value["index"];
    size_t bondCount(0);
    if (value.isArray()) {
      bondCount = static_cast<size_t>(value.size() / 2);
      for (unsigned int i = 0; i < bondCount * 2; i += 2) {
        molecule.addBond(molecule.atom(value.get(i + 0, 0).asInt()),
                         molecule.atom(value.get(i + 1, 0).asInt()));
      }
    }
    else {
      appendError("Warning, no bonding information found.");
    }

    value = bonds["order"];
    if (value.isArray()) {
      if (bondCount != static_cast<size_t>(value.size())) {
        appendError("Error: number of bonds != number of bond orders.");
        return false;
      }
      for (unsigned int i = 0; i < bondCount; ++i)
        molecule.bond(i).setOrder(
          static_cast<unsigned char>(value.get(i, 1).asInt()));
    }
  }

  return true;
}

bool CjsonFormat::write(std::ostream &file, const Core::Molecule &molecule)
{
  Json::StyledStreamWriter writer("  ");
  Json::Value root;

  root["chemical json"] = 0;

  if (molecule.data("name").type() == Variant::String)
    root["name"] = molecule.data("name").toString().c_str();
  if (molecule.data("inchi").type() == Variant::String)
    root["inchi"] = molecule.data("inchi").toString().c_str();

  // Create and populate the atom arrays.
  Json::Value elements(Json::arrayValue);
  Json::Value coords3d(Json::arrayValue);
  Json::Value coords2d(Json::arrayValue);
  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Atom atom = molecule.atom(i);
    elements.append(atom.atomicNumber());
    coords3d.append(atom.position3d().x());
    coords3d.append(atom.position3d().y());
    coords3d.append(atom.position3d().z());
  }
  if (molecule.atomCount()) {
    root["atoms"]["elements"]["number"] = elements;
    root["atoms"]["coords"]["3d"] = coords3d;
  }

  // Create and populate the bond arrays.
  if (molecule.bondCount()) {
    Json::Value connections(Json::arrayValue);
    Json::Value order(Json::arrayValue);
    for (size_t i = 0; i < molecule.bondCount(); ++i) {
      Bond bond = molecule.bond(i);
      connections.append(static_cast<Json::Value::UInt>(bond.atom1().index()));
      connections.append(static_cast<Json::Value::UInt>(bond.atom2().index()));
      order.append(bond.order());
    }
    root["bonds"]["connections"]["index"] = connections;
    root["bonds"]["order"] = order;
  }

  writer.write(file, root);

  return true;
}

std::vector<std::string> CjsonFormat::fileExtensions() const
{
  std::vector<std::string> ext;
  ext.push_back("cjson");
  return ext;
}

std::vector<std::string> CjsonFormat::mimeTypes() const
{
  std::vector<std::string> mime;
  mime.push_back("chemical/x-cjson");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
