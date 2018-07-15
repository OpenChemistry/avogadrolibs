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
#include <avogadro/core/utilities.h>

#include <json/json.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
using Core::split;
using Core::lexicalCast;

CjsonFormat::CjsonFormat() = default;

CjsonFormat::~CjsonFormat() = default;

bool setJsonKey(json& j, Molecule& m, const std::string& key)
{
  if (j.count(key) && j.find(key)->is_string()) {
    std::cout << "Setting " << key << " -> " << j.value(key, "undefined") << std::endl;
    m.setData(key, j.value(key, "undefined"));
    return true;
  }
  std::cout << key << " not found." << std::endl;
  return false;
}

bool isNumericArray(json& j)
{
  if (j.is_array() && j.size() > 0) {
    for (unsigned int i = 0; i < j.size(); ++i) {
      json v = j[i];
      if (!v.is_number()) {
        std::cout << "Not a number at " << i << " in " << j << std::endl;
        return false;
      }
    }
  return true;
  }
  return false;
}

bool isBooleanArray(json& j)
{
  if (j.is_array() && j.size() > 0) {
    for (unsigned int i = 0; i < j.size(); ++i) {
      json v = j[i];
      if (!v.is_boolean()) {
        std::cout << "Not a boolean at " << i << " in " << j << std::endl;
        return false;
      }
    }
  return true;
  }
  return false;
}

bool CjsonFormat::read(std::istream& file, Molecule& molecule)
{
  json jsonRoot = json::parse(file, nullptr, false);
  if (jsonRoot.is_discarded()) {
    appendError("Error parsing JSON.");
    return false;
  }

  if (!jsonRoot.is_object())  {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  auto jsonValue = jsonRoot.find("chemical json");
  if (jsonValue == jsonRoot.end()) {
    appendError("Error: no \"chemical json\" key found.");
    return false;
  }
  if (*jsonValue != 0) {
    appendError("Warning: chemical json version is not 0.");
  }

  // Read some basic key-value pairs (all strings).
  setJsonKey(jsonRoot, molecule, "name");
  setJsonKey(jsonRoot, molecule, "inchi");
  setJsonKey(jsonRoot, molecule, "formula");

  // Read in the atoms.
  json atoms = jsonRoot["atoms"];
  if (!atoms.is_object()) {
    appendError("The 'atoms' key does not contain an object.");
    return false;
  }

  json atomicNumbers = atoms["elements"]["number"];
  // This represents our minimal spec for a molecule - atoms that have an
  // atomic number.
  if (isNumericArray(atomicNumbers) && atomicNumbers.size() > 0) {
    for (unsigned int i = 0; i < atomicNumbers.size(); ++i)
      molecule.addAtom(atomicNumbers[i]);
  } else {
    appendError("Malformed array for in atoms.elements.number");
    return false;
  }
  Index atomCount = molecule.atomCount();

  // 3d coordinates if available for our atoms
  json atomicCoords = atoms["coords"]["3d"];
  if (isNumericArray(atomicCoords) && atomicCoords.size() == 3 * atomCount) {
    for (Index i = 0; i < atomCount; ++i) {
      auto a = molecule.atom(i);
      a.setPosition3d(Vector3(atomicCoords[3 * i],
                              atomicCoords[3 * i + 1],
                              atomicCoords[3 * i + 2]));
    }
  }

  // Selection is optional, but if present should be loaded.
  json selection = atoms["selected"];
  if (isBooleanArray(selection) && selection.size() == atomCount)
    for (Index i = 0; i < atomCount; ++i)
      molecule.setAtomSelected(i, selection[i]);
  else if (isNumericArray(selection) && selection.size() == atomCount)
    for (Index i = 0; i < atomCount; ++i)
      molecule.setAtomSelected(i, selection[i] != 0);

  // Bonds are optional, but if present should be loaded.
  json bonds = jsonRoot["bonds"];
  if (bonds.is_object() && isNumericArray(bonds["connections"]["index"])) {
    json connections = bonds["connections"]["index"];
    for (unsigned int i = 0; i < connections.size() / 2; ++i) {
      molecule.addBond(static_cast<Index>(connections[2 * i]),
                       static_cast<Index>(connections[2 * i + 1]), 1);
    }
    json order = bonds["order"];
    if (isNumericArray(order)) {
      for (unsigned int i = 0; i < molecule.bondCount() && i < order.size();
           ++i) {
        molecule.bond(i).setOrder(static_cast<int>(order[i]));
      }
    }
  }

  json unitCell = jsonRoot["unit cell"];
  if (!unitCell.is_object())
    unitCell = jsonRoot["unitCell"];
  if (unitCell.is_object() && unitCell["a"].is_number()
      && unitCell["b"].is_number() && unitCell["c"].is_number()
      && unitCell["alpha"].is_number() && unitCell["beta"].is_number()
      && unitCell["gamma"].is_number()) {
    Real a = static_cast<Real>(unitCell["a"]);
    Real b = static_cast<Real>(unitCell["b"]);
    Real c = static_cast<Real>(unitCell["c"]);
    Real alpha = static_cast<Real>(unitCell["alpha"]) * DEG_TO_RAD;
    Real beta = static_cast<Real>(unitCell["beta"]) * DEG_TO_RAD;
    Real gamma = static_cast<Real>(unitCell["gamma"]) * DEG_TO_RAD;
    Core::UnitCell* unitCellObject =
      new Core::UnitCell(a, b, c, alpha, beta, gamma);
    molecule.setUnitCell(unitCellObject);
  }
  json fractional = atoms["coords"]["3d fractional"];
  if (!fractional.is_array())
    fractional = atoms["coords"]["3dFractional"];
  if (fractional.is_array() && fractional.size() == 3 * atomCount
      && isNumericArray(fractional) && molecule.unitCell() ) {
      Array<Vector3> fcoords;
      fcoords.reserve(atomCount);
      for (Index i = 0; i < atomCount; ++i) {
        fcoords.push_back(
          Vector3(static_cast<Real>(fractional[i * 3 + 0]),
                  static_cast<Real>(fractional[i * 3 + 1]),
                  static_cast<Real>(fractional[i * 3 + 2])));
      }
      CrystalTools::setFractionalCoordinates(molecule, fcoords);
  }

  // Basis set is optional, if present read it in.
  json basisSet = jsonRoot["basisSet"];
  if (basisSet.is_object()) {
    GaussianSet* basis = new GaussianSet;
    basis->setMolecule(&molecule);
    // Gather the relevant pieces together so that they can be read in.
    json shellTypes = basisSet["shellTypes"];
    json primitivesPerShell = basisSet["primitivesPerShell"];
    json shellToAtomMap = basisSet["shellToAtomMap"];
    json exponents = basisSet["exponents"];
    json coefficients = basisSet["coefficients"];

    int nGTO = 0;
    for (unsigned int i = 0; i < shellTypes.size(); ++i) {
      GaussianSet::orbital type;
      switch (static_cast<int>(shellTypes[i])) {
        case 0:
          type = GaussianSet::S;
          break;
        case 1:
          type = GaussianSet::P;
          break;
        case 2:
          type = GaussianSet::D;
          break;
        case -2:
          type = GaussianSet::D5;
          break;
        default:
          // If we encounter GTOs we do not understand, the basis is likely
          // invalid
          type = GaussianSet::UU;
      }
      if (type != GaussianSet::UU) {
        int b = basis->addBasis(static_cast<int>(shellToAtomMap[i]), type);
        for (int j = 0; j < static_cast<int>(primitivesPerShell[i]); ++j) {
          basis->addGto(b, coefficients[nGTO], exponents[nGTO]);
          ++nGTO;
        }
      }
    }

    json orbitals = jsonRoot["orbitals"];
    if (orbitals.is_object() && basis->isValid()) {
      basis->setElectronCount(orbitals["electronCount"]);
      json moCoefficients = orbitals["alpha"];
      json moCoefficientsA = orbitals["alpha"];
      json moCoefficientsB = orbitals["beta"];
      if (isNumericArray(moCoefficients)) {
        std::vector<double> coeffs;
        for (unsigned int i = 0; i < moCoefficients.size(); ++i)
          coeffs.push_back(static_cast<double>(moCoefficients[i]));
        basis->setMolecularOrbitals(coeffs);
      } else {
        std::cout << "No orbital cofficients found!" << std::endl;
      }
    }

    molecule.setBasisSet(basis);
  }

  // See if there is any vibration data, load it if so.
  json vibrations = jsonRoot["vibrations"];
  if (vibrations.is_object()) {
    json frequencies = vibrations["frequencies"];
    if (isNumericArray(frequencies)) {
      Array<double> freqs;
      for (unsigned int i = 0; i < frequencies.size(); ++i) {
        freqs.push_back(static_cast<double>(frequencies[i]));
      }
      molecule.setVibrationFrequencies(freqs);
    }
    json intensities = vibrations["intensities"];
    if (isNumericArray(intensities)) {
      Array<double> intens;
      for (unsigned int i = 0; i < intensities.size(); ++i) {
        intens.push_back(static_cast<double>(intensities[i]));
      }
      molecule.setVibrationIntensities(intens);
    }
    json displacements = vibrations["eigenVectors"];
    if (displacements.is_array()) {
      Array<Array<Vector3>> disps;
      for (unsigned int i = 0; i < displacements.size(); ++i) {
        json arr = displacements[i];
        if (isNumericArray(arr)) {
          Array<Vector3> mode;
          mode.resize(arr.size() / 3);
          double *ptr = &mode[0][0];
          for (unsigned int j = 0; j < arr.size(); ++j) {
            *(ptr++) = static_cast<double>(arr[j]);
          }
          disps.push_back(mode);
        }
      }
      molecule.setVibrationLx(disps);
    }
  }

  return true;
}

bool CjsonFormat::write(std::ostream& file, const Molecule& molecule)
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
    unitCell["beta"] = molecule.unitCell()->beta() * RAD_TO_DEG;
    unitCell["gamma"] = molecule.unitCell()->gamma() * RAD_TO_DEG;
    root["unit cell"] = unitCell;
  }

  // Write out the basis set if we have one. FIXME: Complete implemnentation.
  if (molecule.basisSet()) {
    Value basis = Value(Json::objectValue);
    const GaussianSet* gaussian =
      dynamic_cast<const GaussianSet*>(molecule.basisSet());
    if (gaussian) {
      basis["basisType"] = "gto";
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
      if (!gaussian->name().empty()) {
        basis["name"] = gaussian->name();
      }

      Value properties(Json::objectValue);
      properties["functionalName"] = gaussian->functionalName();
      properties["electronCount"] = gaussian->electronCount();
      properties["theory"] = gaussian->theoryName();
      properties["scfType"] = type;

      Value mo(Json::objectValue);

      std::vector<double> energies = gaussian->moEnergy();
      if (energies.size() > 0) {
        Value energyData(Json::arrayValue);
        for (vector<double>::const_iterator it = energies.begin(),
                                            itEnd = energies.end();
             it != itEnd; ++it) {
          energyData.append(*it);
        }
        mo["energies"] = energyData;
      }
      std::vector<unsigned char> occ = gaussian->moOccupancy();
      if (occ.size() > 0) {
        Value occData(Json::arrayValue);
        for (vector<unsigned char>::const_iterator it = occ.begin(),
                                                   itEnd = occ.end();
             it != itEnd; ++it) {
          occData.append(static_cast<int>(*it));
        }
        mo["occpupations"] = occData;
      }
      std::vector<unsigned int> num = gaussian->moNumber();
      if (num.size() > 0) {
        Value numData(Json::arrayValue);
        for (vector<unsigned int>::const_iterator it = num.begin(),
                                                  itEnd = num.end();
             it != itEnd; ++it) {
          numData.append(*it);
        }
        mo["numbers"] = numData;
      }

      root["basisSet"] = basis;
      root["molecularOrbitals"] = mo;
      root["properties"] = properties;
    }
  }

  // Write out any cubes that are present in the molecule.
  if (molecule.cubeCount() > 0) {
    const Cube* cube = molecule.cube(0);
    Value cubeData(Json::arrayValue);
    for (vector<double>::const_iterator it = cube->data()->begin(),
                                        itEnd = cube->data()->end();
         it != itEnd; ++it) {
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
    Value selected(Json::arrayValue);
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      elements.append(molecule.atom(i).atomicNumber());
      selected.append(static_cast<int>(molecule.atomSelected(i)));
    }
    root["atoms"]["elements"]["number"] = elements;
    root["atoms"]["selected"] = selected;

    // 3d positions:
    if (molecule.atomPositions3d().size() == molecule.atomCount()) {
      if (molecule.unitCell()) {
        Value coordsFractional(Json::arrayValue);
        Array<Vector3> fcoords;
        CrystalTools::fractionalCoordinates(
          *molecule.unitCell(), molecule.atomPositions3d(), fcoords);
        for (vector<Vector3>::const_iterator it = fcoords.begin(),
                                             itEnd = fcoords.end();
             it != itEnd; ++it) {
          coordsFractional.append(it->x());
          coordsFractional.append(it->y());
          coordsFractional.append(it->z());
        }
        root["atoms"]["coords"]["3d fractional"] = coordsFractional;
      } else {
        Value coords3d(Json::arrayValue);
        for (vector<Vector3>::const_iterator
               it = molecule.atomPositions3d().begin(),
               itEnd = molecule.atomPositions3d().end();
             it != itEnd; ++it) {
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
             itEnd = molecule.atomPositions2d().end();
           it != itEnd; ++it) {
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
    assert(molecule.vibrationFrequencies().size() ==
           molecule.vibrationIntensities().size());
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
