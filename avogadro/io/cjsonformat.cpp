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
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <json/json.h>

namespace Avogadro {
namespace Io {

using std::string;
using std::vector;

using Json::Value;
using Json::Reader;
using Json::StyledStreamWriter;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Cube;
using Core::Elements;
using Core::GaussianSet;
using Core::Molecule;
using Core::Variant;

CjsonFormat::CjsonFormat()
{
}

CjsonFormat::~CjsonFormat()
{
}

bool readUnitCell(Value &root, Molecule &molecule){
  Value value = root["unit cell"];
  if (value.type() == Json::objectValue) {
    if (!value["a"].isNumeric() ||
        !value["b"].isNumeric() ||
        !value["c"].isNumeric() ||
        !value["alpha"].isNumeric() ||
        !value["beta"].isNumeric() ||
        !value["gamma"].isNumeric()) {
      appendError("Invalid unit cell specification: a, b, c, alpha, beta, gamma"
                  " must be present and numeric.");
      return false;
    }
    Real a = static_cast<Real>(value["a"].asDouble());
    Real b = static_cast<Real>(value["b"].asDouble());
    Real c = static_cast<Real>(value["c"].asDouble());
    Real alpha = static_cast<Real>(value["alpha"].asDouble()) * DEG_TO_RAD;
    Real beta  = static_cast<Real>(value["beta" ].asDouble()) * DEG_TO_RAD;
    Real gamma = static_cast<Real>(value["gamma"].asDouble()) * DEG_TO_RAD;
    Core::UnitCell *unitCell = new Core::UnitCell(a, b, c, alpha, beta, gamma);
    molecule.setUnitCell(unitCell);
  }

  return true;
}

bool readProperties(Value &root, Molecule &molecule){
  return true;
}

bool readAtoms(Value &root, Molecule &molecule){
  // Read in the atomic data.
  Value atoms = root["atoms"];
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

  Index atomCount(0);
  if (value.isArray()) {
    atomCount = static_cast<Index>(value.size());
    for (Index i = 0; i < atomCount; ++i)
      molecule.addAtom(static_cast<unsigned char>(value.get(i, 0).asInt()));
  }
  else {
    appendError("Error: \"atoms.elements.number\" is not of type array");
    return false;
  }

  Value coords = atoms["coords"];
  if (!coords.empty()) {
    value = coords["3d"];
    if (value.isArray()) {
      if (value.size() && atomCount != static_cast<Index>(value.size() / 3)) {
        appendError("Error: number of elements != number of 3D coordinates.");
        return false;
      }
      for (Index i = 0; i < atomCount; ++i) {
        Atom a = molecule.atom(i);
        a.setPosition3d(Vector3(value.get(3 * i + 0, 0).asDouble(),
                                value.get(3 * i + 1, 0).asDouble(),
                                value.get(3 * i + 2, 0).asDouble()));
      }
    }

    value = coords["2d"];
    if (value.isArray()) {
      if (value.size() && atomCount != static_cast<Index>(value.size() / 2)) {
        appendError("Error: number of elements != number of 2D coordinates.");
        return false;
      }
      for (Index i = 0; i < atomCount; ++i) {
        Atom a = molecule.atom(i);
        a.setPosition2d(Vector2(value.get(2 * i + 0, 0).asDouble(),
                                value.get(2 * i + 1, 0).asDouble()));
      }
    }

    value = coords["3d fractional"];
    if (value.type() == Json::arrayValue) {
      if (!molecule.unitCell()) {
        appendError("Cannot interpret fractional coordinates without "
                    "unit cell.");
        return false;
      }
      if (value.size() && atomCount != static_cast<size_t>(value.size() / 3)) {
        appendError("Error: number of elements != number of fractional "
                    "coordinates.");
        return false;
      }
      Array<Vector3> fcoords;
      fcoords.reserve(atomCount);
      for (Index i = 0; i < atomCount; ++i) {
        fcoords.push_back(
              Vector3(static_cast<Real>(value.get(i * 3 + 0, 0).asDouble()),
                      static_cast<Real>(value.get(i * 3 + 1, 0).asDouble()),
                      static_cast<Real>(value.get(i * 3 + 2, 0).asDouble())));
      }
      CrystalTools::setFractionalCoordinates(molecule, fcoords);
    }
  }

  return true;
}

bool readOptimization(Value &root, Molecule &molecule){
  return true;
}

bool readVibrations(Value &root, Molecule &molecule){
  // Check for vibrational data.
  Value vibrations = root["vibrations"];
  if (!vibrations.empty() && vibrations.isObject()) {
    Value modes = vibrations["modes"];
    Value freqs = vibrations["frequencies"];
    Value inten = vibrations["intensities"];
    Value eigenVectors = vibrations["eigenVectors"];
    assert(modes.size() == freqs.size());
    assert(modes.size() == inten.size());
    assert(modes.size() == eigenVectors.size());
    Array<double> frequencies;
    Array<double> intensities;
    Array< Array<Vector3> > Lx;
    for (size_t i = 0; i < modes.size(); ++i) {
      frequencies.push_back(freqs.get(i, 0).asDouble());
      intensities.push_back(inten.get(i, 0).asDouble());
      Array<Vector3> modeLx;
      Value lx = eigenVectors.get(i, 0);
      if (!lx.empty() && lx.isArray()) {
        modeLx.resize(lx.size() / 3);
        for (size_t k = 0; k < lx.size(); ++k)
          modeLx[k / 3][k % 3] = lx.get(k, 0).asDouble();
        Lx.push_back(modeLx);
      }
    }
    molecule.setVibrationFrequencies(frequencies);
    molecule.setVibrationIntensities(intensities);
    molecule.setVibrationLx(Lx);
  }

  return true;
}

bool readBonds(Value &root, Molecule &molecule){
  // Now for the bonding data.
  Value bonds = root["bonds"];
  if (!bonds.empty()) {
    value = bonds["connections"];
    if (value.empty()) {
      appendError("Error: no \"bonds.connections\" key found");
      return false;
    }

    value = value["index"];
    Index bondCount(0);
    if (value.isArray()) {
      bondCount = static_cast<Index>(value.size() / 2);
      for (Index i = 0; i < bondCount * 2; i += 2) {
        molecule.addBond(
              molecule.atom(static_cast<Index>(value.get(i + 0, 0).asInt())),
              molecule.atom(static_cast<Index>(value.get(i + 1, 0).asInt())));
      }
    }
    else {
      appendError("Warning, no bonding information found.");
    }

    value = bonds["order"];
    if (value.isArray()) {
      if (bondCount != static_cast<Index>(value.size())) {
        appendError("Error: number of bonds != number of bond orders.");
        return false;
      }
      for (Index i = 0; i < bondCount; ++i)
        molecule.bond(i).setOrder(
          static_cast<unsigned char>(value.get(i, 1).asInt()));
    }
  }

  return true;
}

bool readTransitions(Value &root, Molecule &molecule){
  return true;
}

bool readFragments(Value &root, Molecule &molecule){
  return true;
}

bool testEmpty(Value &value, std::string &key){
  if (value.empty()) {
    string errorKey = "Error: no \"" + key +"\" key found";
    appendError(errorKey);
    return true;
  }
  return false;
}

bool testIsNotObject(Value &value, std::string &key){
  if (value.type() != Json::objectValue) {
    string errorKey = "Error: \"" + key + "\" is not of type object";
    appendError(errorKey);
    return true;
  }
  return false;
}

bool testIfArray(Value &value, std::string &key){
  if(!value.isArray()){
    appendError("Error: \""+ key + "\" is not of type array");
    return false;
  }
  return true;
}


bool CjsonFormat::read(std::istream &file, Molecule &molecule)
{
  Value root;
  Reader reader;
  bool ok = reader.parse(file, root);
  if (!ok) {
    appendError("Error parsing JSON: " + reader.getFormatedErrorMessages());
    return false;
  }

  if (!root.isObject()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  Value value = root["chemical json"];
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

  value = root["formula"];
  if (!value.empty() && value.isString())
    molecule.setData("formula", value.asString());

  return readUnitCell(root, molecule) &&
         readProperties(root, molecule) &&
         readAtoms(root, molecule) &&
         readOptimization(root, molecule) &&
         readVibrations(root, molecule) &&
         readBonds(root, molecule) &&
         readTransitions(root, molecule) &&
         readFragments(root, molecule);
}

bool CjsonFormat::write(std::ostream &file, const Molecule &molecule)
{
  StyledStreamWriter writer("  ");
  Value root;

  root["chemical json"] = 0;

  if (molecule.data("name").type() == Variant::String)
    root["name"] = molecule.data("name").toString().c_str();
  if (molecule.data("inchi").type() == Variant::String)
    root["inchi"] = molecule.data("inchi").toString().c_str();

  if (molecule.unitCell()) {
    Value unitCell = Value(Json::objectValue);
    unitCell["a"] = molecule.unitCell()->a();
    unitCell["b"] = molecule.unitCell()->b();
    unitCell["c"] = molecule.unitCell()->c();
    unitCell["alpha"] = molecule.unitCell()->alpha() * RAD_TO_DEG;
    unitCell["beta"]  = molecule.unitCell()->beta()  * RAD_TO_DEG;
    unitCell["gamma"] = molecule.unitCell()->gamma() * RAD_TO_DEG;
    root["unit cell"] = unitCell;
  }

  // Write out the basis set if we have one. FIXME: Complete implemnentation.
  if (molecule.basisSet()) {
    Value basis = Value(Json::objectValue);
    const GaussianSet *gaussian =
        dynamic_cast<const GaussianSet *>(molecule.basisSet());
    if (gaussian) {
      basis["basisType"] = "GTO";
      string type = "unknown";
      switch (gaussian->scfType()) {
      case Core::Rhf:
        type = "rhf";
        break;
      case Core::Rohf:
        type = "rohf";
        break;
      case Core::Uhf:
        type = "uhf";
        break;
      default:
        type = "unknown";
      }
      basis["scfType"] = type;
      basis["electronCount"] = gaussian->electronCount();
      Value mo(Json::objectValue);

      std::vector<double> energies = gaussian->moEnergy();
      if (energies.size() > 0) {
        Value energyData(Json::arrayValue);
        for (vector<double>::const_iterator it = energies.begin(),
             itEnd = energies.end(); it != itEnd; ++it) {
          energyData.append(*it);
        }
        mo["energies"] = energyData;
      }
      std::vector<unsigned char> occ = gaussian->moOccupancy();
      if (occ.size() > 0) {
        Value occData(Json::arrayValue);
        for (vector<unsigned char>::const_iterator it = occ.begin(),
             itEnd = occ.end(); it != itEnd; ++it) {
          occData.append(static_cast<int>(*it));
        }
        mo["occpupations"] = occData;
      }
      std::vector<unsigned int> num = gaussian->moNumber();
      if (num.size() > 0) {
        Value numData(Json::arrayValue);
        for (vector<unsigned int>::const_iterator it = num.begin(),
             itEnd = num.end(); it != itEnd; ++it) {
          numData.append(*it);
        }
        mo["numbers"] = numData;
      }

      root["basisSet"] = basis;
      root["molecularOrbitals"] = mo;
    }
  }

  // Write out any cubes that are present in the molecule.
  if (molecule.cubeCount() > 0) {
    const Cube *cube = molecule.cube(0);
    Value cubeData(Json::arrayValue);
    const std::vector<double> &v = *cube->data();
    for (vector<double>::const_iterator it = cube->data()->begin(),
         itEnd = cube->data()->end(); it != itEnd; ++it) {
      cubeData.append(*it);
    }
    // Get the origin, max, spacing, and dimensions to place in the object.
    Value cubeObj;
    Value cubeMin(Json::arrayValue);
    cubeMin.append(cube->min().x());
    cubeMin.append(cube->min().y());
    cubeMin.append(cube->min().z());
    cubeObj["origin"] = cubeMin;
    Value cubeSpacing(Json::arrayValue);
    cubeSpacing.append(cube->spacing().x());
    cubeSpacing.append(cube->spacing().y());
    cubeSpacing.append(cube->spacing().z());
    cubeObj["spacing"] = cubeSpacing;
    Value cubeDims(Json::arrayValue);
    cubeDims.append(cube->dimensions().x());
    cubeDims.append(cube->dimensions().y());
    cubeDims.append(cube->dimensions().z());
    cubeObj["dimensions"] = cubeDims;
    cubeObj["scalars"] = cubeData;
    root["cube"] = cubeObj;

  }

  // Create and populate the atom arrays.
  if (molecule.atomCount()) {
    Value elements(Json::arrayValue);
    for (Index i = 0; i < molecule.atomCount(); ++i)
      elements.append(molecule.atom(i).atomicNumber());
    root["atoms"]["elements"]["number"] = elements;

    // 3d positions:
    if (molecule.atomPositions3d().size() == molecule.atomCount()) {
      if (molecule.unitCell()) {
        Value coordsFractional(Json::arrayValue);
        Array<Vector3> fcoords;
        CrystalTools::fractionalCoordinates(*molecule.unitCell(),
                                            molecule.atomPositions3d(),
                                            fcoords);
        for (vector<Vector3>::const_iterator it = fcoords.begin(),
             itEnd = fcoords.end(); it != itEnd; ++it) {
          coordsFractional.append(it->x());
          coordsFractional.append(it->y());
          coordsFractional.append(it->z());
        }
        root["atoms"]["coords"]["3d fractional"] = coordsFractional;
      }
      else {
        Value coords3d(Json::arrayValue);
        for (vector<Vector3>::const_iterator
             it = molecule.atomPositions3d().begin(),
             itEnd = molecule.atomPositions3d().end(); it != itEnd; ++it) {
          coords3d.append(it->x());
          coords3d.append(it->y());
          coords3d.append(it->z());
        }
        root["atoms"]["coords"]["3d"] = coords3d;
      }
    }

    // 2d positions:
    if (molecule.atomPositions2d().size() == molecule.atomCount()) {
      Value coords2d(Json::arrayValue);
      for (vector<Vector2>::const_iterator
           it = molecule.atomPositions2d().begin(),
           itEnd = molecule.atomPositions2d().end(); it != itEnd; ++it) {
        coords2d.append(it->x());
        coords2d.append(it->y());
      }
      root["atoms"]["coords"]["2d"] = coords2d;
    }
  }

  // Create and populate the bond arrays.
  if (molecule.bondCount()) {
    Value connections(Json::arrayValue);
    Value order(Json::arrayValue);
    for (Index i = 0; i < molecule.bondCount(); ++i) {
      Bond bond = molecule.bond(i);
      connections.append(static_cast<Value::UInt>(bond.atom1().index()));
      connections.append(static_cast<Value::UInt>(bond.atom2().index()));
      order.append(bond.order());
    }
    root["bonds"]["connections"]["index"] = connections;
    root["bonds"]["order"] = order;
  }

  // If there is vibrational data write this out too.
  if (molecule.vibrationFrequencies().size() > 0) {
    // A few sanity checks before we begin.
    assert(molecule.vibrationFrequencies().size()
           == molecule.vibrationIntensities().size());
    Value modes(Json::arrayValue);
    Value freqs(Json::arrayValue);
    Value inten(Json::arrayValue);
    Value eigenVectors(Json::arrayValue);
    for (size_t i = 0; i < molecule.vibrationFrequencies().size(); ++i) {
      modes.append(static_cast<unsigned int>(i) + 1);
      freqs.append(molecule.vibrationFrequencies()[i]);
      inten.append(molecule.vibrationIntensities()[i]);
      Core::Array<Vector3> atomDisplacements = molecule.vibrationLx(i);
      Value eigenVector(Json::arrayValue);
      for (size_t j = 0; j < atomDisplacements.size(); ++j) {
        Vector3 pos = atomDisplacements[j];
        eigenVector.append(pos[0]);
        eigenVector.append(pos[1]);
        eigenVector.append(pos[2]);
      }
      eigenVectors.append(eigenVector);
    }
    root["vibrations"]["modes"] = modes;
    root["vibrations"]["frequencies"] = freqs;
    root["vibrations"]["intensities"] = inten;
    root["vibrations"]["eigenVectors"] = eigenVectors;
  }

  writer.write(file, root);

  return true;
}

vector<std::string> CjsonFormat::fileExtensions() const
{
  vector<std::string> ext;
  ext.push_back("cjson");
  return ext;
}

vector<std::string> CjsonFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.push_back("chemical/x-cjson");
  return mime;
}

} // end Io namespace
} // end Avogadro namespace
