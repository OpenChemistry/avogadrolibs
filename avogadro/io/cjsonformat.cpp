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

#include <nlohmann/json.hpp>

#include <iostream>

using json = nlohmann::json;

namespace Avogadro {
namespace Io {

using std::string;
using std::vector;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Cube;
using Core::Elements;
using Core::GaussianSet;
using Core::lexicalCast;
using Core::Molecule;
using Core::split;
using Core::Variant;

CjsonFormat::CjsonFormat() = default;

CjsonFormat::~CjsonFormat() = default;

bool setJsonKey(json& j, Molecule& m, const std::string& key)
{
  if (j.count(key) && j.find(key)->is_string()) {
    m.setData(key, j.value(key, "undefined"));
    return true;
  }
  return false;
}

bool isNumericArray(json& j)
{
  if (j.is_array() && j.size() > 0) {
    for (unsigned int i = 0; i < j.size(); ++i) {
      json v = j[i];
      if (!v.is_number()) {
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

  if (!jsonRoot.is_object()) {
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
      a.setPosition3d(Vector3(atomicCoords[3 * i], atomicCoords[3 * i + 1],
                              atomicCoords[3 * i + 2]));
    }
  }

  // Check for coordinate sets, and read them in if found, e.g. trajectories.
  json coordSets = atoms["coordSets"];
  if (coordSets.is_array() && coordSets.size()) {
    for (unsigned int i = 0; i < coordSets.size(); ++i) {
      Array<Vector3> setArray;
      json set = coordSets[i];
      if (isNumericArray(set)) {
        for (unsigned int j = 0; j < set.size() / 3; ++j) {
          setArray.push_back(Vector3(set[3 * j], set[3 * j + 1],
                                     set[3 * j + 2]));
        }
        molecule.setCoordinate3d(setArray, i);
      }
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
  if (unitCell.is_object() && unitCell["a"].is_number() &&
      unitCell["b"].is_number() && unitCell["c"].is_number() &&
      unitCell["alpha"].is_number() && unitCell["beta"].is_number() &&
      unitCell["gamma"].is_number()) {
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
  if (fractional.is_array() && fractional.size() == 3 * atomCount &&
      isNumericArray(fractional) && molecule.unitCell()) {
    Array<Vector3> fcoords;
    fcoords.reserve(atomCount);
    for (Index i = 0; i < atomCount; ++i) {
      fcoords.push_back(Vector3(static_cast<Real>(fractional[i * 3 + 0]),
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
      json moCoefficients = orbitals["moCoefficients"];
      json moCoefficientsA = orbitals["alphaCoefficients"];
      json moCoefficientsB = orbitals["betaCoefficients"];
      if (isNumericArray(moCoefficients)) {
        std::vector<double> coeffs;
        for (unsigned int i = 0; i < moCoefficients.size(); ++i)
          coeffs.push_back(static_cast<double>(moCoefficients[i]));
        basis->setMolecularOrbitals(coeffs);
      } else if (isNumericArray(moCoefficientsA) &&
                 isNumericArray(moCoefficientsB)) {
        std::vector<double> coeffsA;
        for (unsigned int i = 0; i < moCoefficientsA.size(); ++i)
          coeffsA.push_back(static_cast<double>(moCoefficientsA[i]));
        std::vector<double> coeffsB;
        for (unsigned int i = 0; i < moCoefficientsB.size(); ++i)
          coeffsB.push_back(static_cast<double>(moCoefficientsB[i]));
        basis->setMolecularOrbitals(coeffsA, BasisSet::Alpha);
        basis->setMolecularOrbitals(coeffsB, BasisSet::Beta);
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
          double* ptr = &mode[0][0];
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
  json root;

  root["chemical json"] = 0;

  if (molecule.data("name").type() == Variant::String)
    root["name"] = molecule.data("name").toString().c_str();
  if (molecule.data("inchi").type() == Variant::String)
    root["inchi"] = molecule.data("inchi").toString().c_str();

  if (molecule.unitCell()) {
    json unitCell;
    unitCell["a"] = molecule.unitCell()->a();
    unitCell["b"] = molecule.unitCell()->b();
    unitCell["c"] = molecule.unitCell()->c();
    unitCell["alpha"] = molecule.unitCell()->alpha() * RAD_TO_DEG;
    unitCell["beta"] = molecule.unitCell()->beta() * RAD_TO_DEG;
    unitCell["gamma"] = molecule.unitCell()->gamma() * RAD_TO_DEG;
    root["unit cell"] = unitCell;
  }

  // Create a basis set/MO matrix we can round trip.
  if (molecule.basisSet() &&
      dynamic_cast<const GaussianSet*>(molecule.basisSet())) {
    json basis;
    auto gaussian = dynamic_cast<const GaussianSet*>(molecule.basisSet());

    // Map the shell types from enumeration to integer values.
    auto symmetry = gaussian->symmetry();
    json shellTypes;
    for (size_t i = 0; i < symmetry.size(); ++i) {
      switch (symmetry[i]) {
        case GaussianSet::S:
          shellTypes.push_back(0);
          break;
        case GaussianSet::P:
          shellTypes.push_back(1);
          break;
        case GaussianSet::D:
          shellTypes.push_back(2);
          break;
        case GaussianSet::D5:
          shellTypes.push_back(-2);
          break;
        default:
          // Something bad, put in a silly number...
          shellTypes.push_back(426942);
      }
    }
    basis["shellTypes"] = shellTypes;

    // This bit is slightly tricky, map from our index to primitives per shell.
    auto gtoIndices = gaussian->gtoIndices();
    auto gtoA = gaussian->gtoA();
    json primitivesPerShell;
    for (size_t i = 0; i < gtoIndices.size() - 1; ++i)
      primitivesPerShell.push_back(gtoIndices[i + 1] - gtoIndices[i]);
    primitivesPerShell.push_back(gtoA.size() - gtoIndices.back());
    basis["primitivesPerShell"] = primitivesPerShell;

    auto atomIndices = gaussian->atomIndices();
    json shellToAtomMap;
    for (size_t i = 0; i < atomIndices.size(); ++i)
      shellToAtomMap.push_back(atomIndices[i]);
    basis["shellToAtomMap"] = shellToAtomMap;

    auto gtoC = gaussian->gtoC();
    json exponents;
    json coefficients;
    for (size_t i = 0; i < gtoA.size(); ++i) {
      exponents.push_back(gtoA[i]);
      coefficients.push_back(gtoC[i]);
    }
    basis["exponents"] = exponents;
    basis["coefficients"] = coefficients;

    root["basisSet"] = basis;

    // Now get the MO matrix, potentially other things. Need to get a handle on
    // when we have just one (paired), or two (alpha and beta) to write.
    auto moMatrix = gaussian->moMatrix();
    auto betaMatrix = gaussian->moMatrix(BasisSet::Beta);
    json moCoefficients;
    for (int j = 0; j < moMatrix.cols(); ++j)
      for (int i = 0; i < moMatrix.rows(); ++i)
        moCoefficients.push_back(moMatrix(i, j));

    if (betaMatrix.cols() > 0 && betaMatrix.rows() > 0) {
      json moBeta;
      for (int j = 0; j < moMatrix.cols(); ++j)
        for (int i = 0; i < moMatrix.rows(); ++i)
          moBeta.push_back(moMatrix(i, j));

      root["orbitals"]["alphaCoefficients"] = moCoefficients;
      root["orbitals"]["betaCoefficients"] = moBeta;
    } else {
      root["orbitals"]["moCoefficients"] = moCoefficients;
    }
    root["orbitals"]["electronCount"] = gaussian->electronCount();
  }

  // Write out any cubes that are present in the molecule.
  if (molecule.cubeCount() > 0) {
    const Cube* cube = molecule.cube(0);
    json cubeData;
    for (vector<double>::const_iterator it = cube->data()->begin(),
                                        itEnd = cube->data()->end();
         it != itEnd; ++it) {
      cubeData.push_back(*it);
    }
    // Get the origin, max, spacing, and dimensions to place in the object.
    json cubeObj;
    json cubeMin;
    cubeMin.push_back(cube->min().x());
    cubeMin.push_back(cube->min().y());
    cubeMin.push_back(cube->min().z());
    cubeObj["origin"] = cubeMin;
    json cubeSpacing;
    cubeSpacing.push_back(cube->spacing().x());
    cubeSpacing.push_back(cube->spacing().y());
    cubeSpacing.push_back(cube->spacing().z());
    cubeObj["spacing"] = cubeSpacing;
    json cubeDims;
    cubeDims.push_back(cube->dimensions().x());
    cubeDims.push_back(cube->dimensions().y());
    cubeDims.push_back(cube->dimensions().z());
    cubeObj["dimensions"] = cubeDims;
    cubeObj["scalars"] = cubeData;
    root["cube"] = cubeObj;
  }

  // Create and populate the atom arrays.
  if (molecule.atomCount()) {
    json elements;
    json selected;
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      elements.push_back(molecule.atom(i).atomicNumber());
      selected.push_back(molecule.atomSelected(i));
    }
    root["atoms"]["elements"]["number"] = elements;
    root["atoms"]["selected"] = selected;

    // 3d positions:
    if (molecule.atomPositions3d().size() == molecule.atomCount()) {
      if (molecule.unitCell()) {
        json coordsFractional;
        Array<Vector3> fcoords;
        CrystalTools::fractionalCoordinates(
          *molecule.unitCell(), molecule.atomPositions3d(), fcoords);
        for (vector<Vector3>::const_iterator it = fcoords.begin(),
                                             itEnd = fcoords.end();
             it != itEnd; ++it) {
          coordsFractional.push_back(it->x());
          coordsFractional.push_back(it->y());
          coordsFractional.push_back(it->z());
        }
        root["atoms"]["coords"]["3d fractional"] = coordsFractional;
      } else {
        json coords3d;
        for (vector<Vector3>::const_iterator
               it = molecule.atomPositions3d().begin(),
               itEnd = molecule.atomPositions3d().end();
             it != itEnd; ++it) {
          coords3d.push_back(it->x());
          coords3d.push_back(it->y());
          coords3d.push_back(it->z());
        }
        root["atoms"]["coords"]["3d"] = coords3d;
      }
    }

    // 2d positions:
    if (molecule.atomPositions2d().size() == molecule.atomCount()) {
      json coords2d;
      for (vector<Vector2>::const_iterator
             it = molecule.atomPositions2d().begin(),
             itEnd = molecule.atomPositions2d().end();
           it != itEnd; ++it) {
        coords2d.push_back(it->x());
        coords2d.push_back(it->y());
      }
      root["atoms"]["coords"]["2d"] = coords2d;
    }
  }

  // Create and populate the bond arrays.
  if (molecule.bondCount()) {
    json connections;
    json order;
    for (Index i = 0; i < molecule.bondCount(); ++i) {
      Bond bond = molecule.bond(i);
      connections.push_back(bond.atom1().index());
      connections.push_back(bond.atom2().index());
      order.push_back(bond.order());
    }
    root["bonds"]["connections"]["index"] = connections;
    root["bonds"]["order"] = order;
  }

  // If there is vibrational data write this out too.
  if (molecule.vibrationFrequencies().size() > 0) {
    // A few sanity checks before we begin.
    assert(molecule.vibrationFrequencies().size() ==
           molecule.vibrationIntensities().size());
    json modes;
    json freqs;
    json inten;
    json eigenVectors;
    for (size_t i = 0; i < molecule.vibrationFrequencies().size(); ++i) {
      modes.push_back(static_cast<unsigned int>(i) + 1);
      freqs.push_back(molecule.vibrationFrequencies()[i]);
      inten.push_back(molecule.vibrationIntensities()[i]);
      Core::Array<Vector3> atomDisplacements = molecule.vibrationLx(i);
      json eigenVector;
      for (size_t j = 0; j < atomDisplacements.size(); ++j) {
        Vector3 pos = atomDisplacements[j];
        eigenVector.push_back(pos[0]);
        eigenVector.push_back(pos[1]);
        eigenVector.push_back(pos[2]);
      }
      eigenVectors.push_back(eigenVector);
    }
    root["vibrations"]["modes"] = modes;
    root["vibrations"]["frequencies"] = freqs;
    root["vibrations"]["intensities"] = inten;
    root["vibrations"]["eigenVectors"] = eigenVectors;
  }

  // Write out the file, use a two space indent to "pretty print".
  file << std::setw(2) << root;

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
