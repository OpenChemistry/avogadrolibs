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

CjsonFormat::CjsonFormat()
{
}

CjsonFormat::~CjsonFormat()
{
}

bool CjsonFormat::testEmpty(Value &value, const std::string &key,
                            bool writeError)
{
  if (value.empty()) {
    if (writeError)
      appendError("Error: no \"" + key +"\" key found");
    return true;
  }
  return false;
}

bool CjsonFormat::testIsNotObject(Value &value, const std::string &key,
                                  bool writeError)
{
  if (value.type() != Json::objectValue) {
    if (writeError)
      appendError("Error: \"" + key + "\" is not of type object");
    return true;
  }
  return false;
}

bool CjsonFormat::testIfArray(Value &value, const std::string &key,
                              bool writeError)
{
  if (!value.isArray()) {
    if (writeError)
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

  // Now create the structure, and expand out the orbitals.
  GaussianSet *basis = new GaussianSet;
  basis->setMolecule(&molecule);

  if (!readAtoms(root, molecule, basis)) {
    appendError("Unable to read in the atoms");
    return false;
  }

  if (!readProperties(root, molecule, basis)) {
    delete basis;
  }
  else {
    molecule.setBasisSet(basis);
  }

  return readOptimization(root, molecule) &&
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

bool CjsonFormat::readProperties(Value &root, Molecule &molecule,
                                 GaussianSet* basis)
{
  //Read in properties of the molecule
  Value properties = root["properties"];
  if (testEmpty(properties, "atoms") || testIsNotObject(properties, "atoms")) {
    return false;
  }

  //From C++11 onwards, check compatibility?
  std::vector<std::string> attributes = {"molecular mass", "charge",
                                         "multiplicity", "total dipole moment",
                                         "enthalpy", "entropy", "temperature"};

  Value value;
  for (Value::iterator it = properties.begin(); it != properties.end(); ++it) {
    if (std::find(attributes.begin(), attributes.end(),
                  it.key().asString()) != attributes.end()) {
      value = *it;
      if (!value.empty() && it.key().isString() && value.isNumeric())
        molecule.setData(it.key().asString(), value.asDouble());
    }
  }

  // Energy attributes start here
  Value energy = properties["energy"];
  if (!(testEmpty(energy, "properties.energy") ||
        testIsNotObject(energy, "properties.energy" ))) {

    value = energy["free energy"];
    if (!value.empty()) {
      molecule.setData("total free energy", value.asDouble());
    }

    value = energy["total"];
    if (!value.empty()) {
      molecule.setData("total energy", value.asDouble());
    }

    //alpha/beta -> homo/gap not read in

    /* Not integrated, variant doesn't support raw C-style arrays
    value = energy["coupled cluster"];
    if (!value.empty() &&
        testIfArray(value, "properties.energy.coupled_cluster")) {
      int energyCount = static_cast<int>(value.size());
      double *ccEnergies = new double[energyCount];
      for(int i = 0; i < energyCount; ++i)
        ccEnergies[i] = value.get(i,0).asDouble();
      molecule.setData("coupled cluster energies", ccEnergies);
    }
    */

    value = energy["moller plesset"];
    if (!value.empty()) {
      int n = static_cast<int>(value.size());
      int L = static_cast<int>(value[0].size());
      MatrixX mpEnergies(n,L);
      Value orderArray;
      for (int i = 0; i < n; ++i) {
        orderArray = value[i];
        for (int j =0; j < L ; j++) {
          mpEnergies(i, j) = orderArray.get(j, 0).asDouble();
        }
      }
      molecule.setData("moller plesset energies", mpEnergies);
    }
  }

  /* Not integrated, variant doesn't support raw C-style arrays
  // Partial Charges attributes start here
  Value pCharges = properties["partial charges"];
  if (!(testEmpty(pCharges, "properties.partialCharges") ||
        testIsNotObject(pCharges, "properties.partialCharges"))) {

    std::vector<std::string> pChargeType = {"mulliken", "lowdin", "natural" };

    for (Value::iterator it = pCharges.begin(); it != pCharges.end(); ++it) {
      if (std::find(pChargeType.begin(), pChargeType.end(),
                    it.key().asString()) != pChargeType.end()) {
        value = *it;

        if (!value.empty() && !value.isArray()) {
          int pcCount = static_cast<int>(value.size());
          double *partialCharge = new double[pcCount];
          for(int i = 0; i < pcCount; ++i)
            partialCharge[i] = value.get(i,0).asDouble();

          string keyName("partialCharge-");
          keyName += it.key().asString();
          molecule.setData(keyName, partialCharge);
        }

      }
    }
  }
  */

  // Orbitals attributes start here
  Value orbitals = properties["orbitals"];
  if (!(testEmpty(orbitals, "properties.orbitals") ||
        testIsNotObject(orbitals, "properties.orbitals" ))) {

    bool unrestricted = false;

    Value homo = orbitals["homos"];
    if (!homo.empty() && homo.isArray()) {
      unrestricted = static_cast<int>(homo.size()) == 2 ? true : false;

      int homoIndex = homo[0].asInt() + 1;
      //Asumption: Only closed shell calculations are parsed
      vector<unsigned char> occArray(homoIndex, static_cast<unsigned char>(2));
      basis->setMolecularOrbitalOccupancy(occArray);

      if (unrestricted) {
        int betaHomoIndex = homo[1].asInt() + 1;
        vector<unsigned char> betaOccArray(betaHomoIndex,
                                           static_cast<unsigned char>(2));
        basis->setMolecularOrbitalOccupancy(betaOccArray);
      }
    }


    // Basis set energy has a one dimension restriction
    Value moEnergies = orbitals["energies"];
    if (!moEnergies.empty() && moEnergies.isArray()) {
      unrestricted = static_cast<int>(moEnergies.size()) == 2 ? true : false;

      value = moEnergies[0];
      int energyCount = static_cast<int>(value.size());
      vector<double> energyArray(energyCount);
      for (int i = 0; i < energyCount; ++i) {
        energyArray[i] = value.get(i,0).asDouble();
      }
      basis->setMolecularOrbitalEnergy(energyArray);

      //For unrestricted calculation beta energies exist
      if (unrestricted) {
        // Assumption: The number of beta energies will be equivalent to alpha
        // energies
        vector<double> betaEnergyArray(energyCount);
        value = moEnergies[1];

        for (int i = 0; i < energyCount;  ++i) {
          betaEnergyArray[i] = value.get(i,0).asDouble();
        }
        basis->setMolecularOrbitalEnergy(betaEnergyArray,  BasisSet::Beta);
      }
    }

    // Overlap between basis functions (atomic orbitals)
    value = orbitals["overlaps"];
    if (!value.empty()) {
      int rows = static_cast<int>(value.size());
      int cols = static_cast<int>(value[0].size());
      MatrixX aoOverlaps(rows,cols);
      Value basisArray;
      for (int i = 0; i < rows; ++i) {
        basisArray = value[i];
        for (int j =0; j < cols ; j++) {
          aoOverlaps(i, j) = basisArray.get(j, 0).asDouble();
        }
      }
      molecule.setData("atomic orbital overlaps", aoOverlaps);
    }

    // To be filled with mocoeffs attribute
    Value moCoeffs = orbitals["coeffs"];
    if (!(testEmpty(moCoeffs, "properties.orbitals.coeffs") ||
          testIfArray(moCoeffs, "properties.orbitals.coeffs" ))) {
      unrestricted = static_cast<int>(moCoeffs.size()) == 2 ? true : false;
      vector<double> coeffArray;

      value = moCoeffs[0];
      if (!value.empty()) {
        for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
          for (Json::ArrayIndex j = 0; j < value[0].size(); ++j) {
            coeffArray.push_back(value[i][j].asDouble());
          }
        }
        basis->setMolecularOrbitals(coeffArray);

        if (unrestricted) {
          coeffArray.clear();
          value = moCoeffs[1];
          if (!value.empty()) {
            for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
              for (Json::ArrayIndex j = 0; j < value[0].size(); ++j) {
                coeffArray.push_back(value[i][j].asDouble());
              }
            }
            basis->setMolecularOrbitals(coeffArray, BasisSet::Beta);
          }
        }
      }

      // Set Density matrix
      // Gaussian set - Density matrix doesn't distinguish between restricted
      // and unrestricted calculations
      if (orbitals.isMember("basis number") && orbitals.isMember("homos")) {
        int basisSize = orbitals["basis number"].asInt();
        int homoIndex = orbitals["homos"][0].asInt() + 1;

        MatrixX densityMatrix(basisSize,basisSize);

        for (int i = 0 ; i < homoIndex ; ++i) {
          MatrixX column(basisSize, 1);
          for (int j = 0; j < basisSize; ++j) {
            column(j, 0) = value[i][j].asDouble();
          }

          MatrixX tempDensity = column * column.transpose();
          densityMatrix += tempDensity;
        }
        basis->setDensityMatrix(densityMatrix);

        if (unrestricted) {
          MatrixX betaDensityMatrix(basisSize,basisSize);
          value = moCoeffs[1];

          for (int i = 0; i < homoIndex; ++i) {
            MatrixX column(basisSize, 1);
            for (int j = 0; j < basisSize; ++j) {
              column(j, 0) = value[i][j].asDouble();
            }

            MatrixX tempDensity = column * column.transpose();
            betaDensityMatrix += tempDensity;
          }

          // Spin Density Matrix = Alpha Density Matrix - Beta Density Matrix
          MatrixX spinDensityMatrix = densityMatrix - betaDensityMatrix;
          basis->setSpinDensityMatrix(spinDensityMatrix);
        }

      }
    }

    /* Not integrated, variant doesn't support templated Array class
    // Molecular orbital symmetries
    Value MOSymmetry = orbitals["molecular orbital symmetry"];
    if (!(testEmpty(moCoeffs, "properties.orbitals.MOSymmetry") ||
          testIfArray(moCoeffs, "properties.orbitals.MOSymmetry" ))) {
      unrestricted = static_cast<int>(MOSymmetry.size()) == 2 ? true : false;
      Array<string> symmetryArray;

      value = MOSymmetry[0];
      if (!value.empty() && value.isArray()) {
        for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
          symmetryArray.push_back(value[i].asString());
        }
        molecule.setData("molecular orbital symmetry", symmetryArray);

        if (unrestricted) {
          Array<string> betaSymmetryArray;
          value = MOSymmetry[1];
          if (!value.empty() && value.isArray()) {
            for (Json::ArrayIndex i = 0; i < value.size(); ++i) {
              betaSymmetryArray.push_back(value[i].asString());
            }
            molecule.setData("beta molecular orbital symmetry",
                             betaSymmetryArray);
          }
        }
      }
    }
    */
  }

  return true;
}

bool CjsonFormat::readAtoms(Value &root, Molecule &molecule, GaussianSet* basis)
{
  // Read in the atomic data.
  Value atoms = root["atoms"];
  if (testEmpty(atoms, "atoms") || testIsNotObject(atoms, "atoms")) {
    return false;
  }

  // Element values start here
  Value value =  atoms["elements"];
  Index atomCount(0);
  if (!(testEmpty(value, "atoms.elements") ||
        testIsNotObject(value, "atoms.elements"))) {
    value = value["number"];

    if (!testEmpty(value, "atoms.elements.number") &&
        testIfArray(value, "atoms.elements.number")) {
      atomCount = static_cast<Index>(value.size());
      for (Index i = 0; i < atomCount; ++i)
        molecule.addAtom(static_cast<unsigned char>(value.get(i, 0).asInt()));
    }
    else {
      return false;
    }
  }

  Value selected = atoms["selected"];
  if (!selected.empty() && selected.isArray()) {
    if (selected.size() && atomCount != static_cast<Index>(selected.size())) {
      appendError("Error: number of selected atoms != number of atoms.");
      return false;
    }
    for (Index i = 0; i < atomCount; ++i) {
      molecule.setAtomSelected(i, selected.get(i, 0).asBool());
    }
  }

  // Start of Coords object
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

    Value unitCell = root["unit cell"];
    if (unitCell.type() == Json::objectValue) {
      if (!unitCell["a"].isNumeric() ||
          !unitCell["b"].isNumeric() ||
          !unitCell["c"].isNumeric() ||
          !unitCell["alpha"].isNumeric() ||
          !unitCell["beta"].isNumeric() ||
          !unitCell["gamma"].isNumeric()) {
        appendError("Invalid unit cell specification: a, b, c, alpha, beta, "
                    "gamma must be present and numeric.");
        return false;
      }
      Real a = static_cast<Real>(unitCell["a"].asDouble());
      Real b = static_cast<Real>(unitCell["b"].asDouble());
      Real c = static_cast<Real>(unitCell["c"].asDouble());
      Real alpha = static_cast<Real>(unitCell["alpha"].asDouble()) * DEG_TO_RAD;
      Real beta  = static_cast<Real>(unitCell["beta" ].asDouble()) * DEG_TO_RAD;
      Real gamma = static_cast<Real>(unitCell["gamma"].asDouble()) * DEG_TO_RAD;
      Core::UnitCell *unitCellObject = new Core::UnitCell(a, b, c,
                                                          alpha, beta, gamma);
      molecule.setUnitCell(unitCellObject);
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

  // Start of Orbitals
  Value orbitals = atoms["orbitals"];
  if (!(testEmpty(orbitals, "atoms.orbitals") ||
        testIsNotObject(orbitals, "atoms.orbitals"))) {

    value = orbitals["names"];
    if (testIfArray(value, "atoms.orbitals.aonames")) {

      // Figure out the mapping of basis set to molecular orbitals.
      Array<int> atomNumber;
      Array<string> atomSymbol;
      for (size_t i = 0; i < value.size(); ++i) {
        string desc = value.get(i, 0).asString();
        vector<string> parts = split(desc, '_');
        assert(parts.size() == 2);
        int num = 0;
        string atomSym;

        //Case where the element symbol is one character, e.g: C, H, O
        if (isdigit(parts[0][1])) {
          num = lexicalCast<int>(parts[0].substr(1));
          atomSym = parts[0][0];
        }//Case where the element symbol is two characters, e.g: Cl, He, Ag
        else {
          num = lexicalCast<int>(parts[0].substr(2));
          atomSym = parts[0].substr(0,2);
        }

        if (atomNumber.size() > 0 && atomNumber.back() == num)
          continue;
        atomNumber.push_back(num);
        atomSymbol.push_back(atomSym);
      }

      Value basisFunctions = orbitals["basis functions"];

      for (size_t i = 0; i < atomSymbol.size(); ++i ) {
        string symbol = atomSymbol[i];
        Value currentFunction = basisFunctions.get(i, 0);

        if (!currentFunction.isArray()) {
          continue;
        }

        for ( size_t j = 0; j < currentFunction.size(); ++j) {
          Value curBasis = currentFunction.get(j, 0);
          string shellType = curBasis[0].asString();

          bool spherical = false; //is this available in cclib?
          GaussianSet::orbital type = GaussianSet::UU;
          if (shellType == "S")
            type = GaussianSet::S;
          else if (shellType == "P")
            type = GaussianSet::P;
          else if (shellType == "D" && spherical)
            type = GaussianSet::D5;
          else if (shellType == "D")
            type = GaussianSet::D;
          else if (shellType == "F" && spherical)
            type = GaussianSet::F7;
          else if (shellType == "F")
            type = GaussianSet::F;

          if (type != GaussianSet::UU) {
            int b = basis->addBasis(i, type);
            for (Json::ArrayIndex k = 0; k < curBasis[1].size(); ++k) {
              double exponent = curBasis[1][k][0].asDouble();
              double coefficient = curBasis[1][k][1].asDouble();
              basis->addGto(b, coefficient, exponent);
            }
          }
        }
      }
    }

    // Atomic orbital indices for all atoms
    value = orbitals["indices"];
    if (testIfArray(value, "atoms.orbitals.aonames")) {
      //post process the saved data
    }
  }

  value = atoms["core electrons"];
  Index coreElectronCount(0);

  if (!testEmpty(value, "atoms.coreElectron") &&
      testIfArray(value, "atoms.coreElectron")) {
    coreElectronCount = static_cast<Index>(value.size());
    for (Index i = 0; i < coreElectronCount; ++i) {
      // Add the derived data to the appropriate place
      break;
    }
  }

  // Start of atomic spins
  Value spins = atoms["spins"];
  if (!testEmpty(spins, "atoms.atomspins") &&
      !testIsNotObject(spins, "atoms.atomspins")) {

    /* Not integrated, variant doesn't support raw C-style arrays
    value = spins["mulliken"];
    if (!value.empty() && !value.isArray()) {
      int spinCount = static_cast<int>(value.size());
      double *atomicSpins = new double[spinCount];
      for(int i = 0; i < spinCount; ++i)
        atomicSpins[i] = value.get(i,0).asDouble();
      molecule.setData("mulliken spin", atomicSpins);
      // Should I delete atomicSpins here after assigning that memory?
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    value = spins["lowdin"];
    if (!value.empty() && !value.isArray()) {
      int spinCount = static_cast<int>(value.size());
      double *atomicSpins = new double[spinCount];
      for(int i = 0; i < spinCount; ++i)
        atomicSpins[i] = value.get(i,0).asDouble();
      molecule.setData("lowdin spin", atomicSpins);
      // Same as above
    }
    */
  }

  return true;
}

bool CjsonFormat::readOptimization(Value &root, Molecule &molecule)
{
  Value optimization = root["optimization"];

  if (!(testEmpty(optimization, "optimization") ||
        testIsNotObject(optimization, "optimization"))) {

    if (optimization.isMember("done")) {
      bool status = optimization["done"].asBool();
      molecule.setData("optimization status", status);
    }

    /* Not integrated, variant doesn't support raw C-style arrays
    Value value;
    if (optimization.isMember("geometric targets")) {
      value = optimization["geometric targets"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        double *geometricTargets = new double[targetCount];
        for (int i = 0; i < targetCount; ++i)
          geometricTargets[i] = value.get(i, 0).asDouble();
        molecule.setData("geometric targets", geometricTargets);
      }
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    if (optimization.isMember("geometric values")) {
      value = optimization["geometric values"];

      if (!value.empty() && !value.isArray()) {
        int valueCount = static_cast<int>(value.size());
        double *geometricValues = new double[valueCount];
        for (int i = 0; i < valueCount; ++i)
          geometricValues[i] = value.get(i, 0).asDouble();
        molecule.setData("geometric values", geometricValues);
      }
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    // Start of SCF object
    Value scf = optimization["scf"];
    if (!scf.empty()) {
      if (scf.isMember("scf energies")) {
        value = scf["scf energies"];

        if (!value.empty() && !value.isArray()) {
          int energyCount = static_cast<int>(value.size());
          double *scfEnergyValues = new double[energyCount];
          for (int i = 0; i < energyCount; ++i)
            scfEnergyValues[i] = value.get(i, 0).asDouble();
          molecule.setData("scf energy values", scfEnergyValues);
        }
      }
    }
    */

    /* Not integrated, variant doesn't support vector of vector of vectors...
    // Start of scan object
    Value scan = optimization["scan"];
    if (!scan.empty()) {
      if (scan.isMember("step geometry")) {
        Value stepG = scan["step geometry"];
        if (stepG.isArray()) {
          vector<vector<vector<double>>> stepGeometry;
          for (Json::ArrayIndex i = 0 ; i < stepG.size() ; ++i ) {
            Value innerStep = stepG.get(i, 0);
            vector<vector<double>> step;
            for (Json::ArrayIndex j = 0 ; j < innerStep.size() ; ++j) {
              value = innerStep.get(j,0);
              vector<double> coordinates;
              for(int k = 0 ; k < 3; ++k){
                coordinates.push_back(value[k].asDouble());
              }
              step.push_back(coordinates);
            }
            stepGeometry.push_back(step);
          }
          molecule.setData("step geometry", &stepGeometry);
        }
      }

      // Not integrated, variant doesn't support raw C-style arrays
      if (scan.isMember("PES energies")){
        value = scan["PES energies"];

        if (!value.empty() && !value.isArray()) {
          int pesEnergyCount = static_cast<int>(value.size());
          double *pesEnergyValues = new double[pesEnergyCount];
          for (int i = 0; i < pesEnergyCount; ++i)
            pesEnergyValues[i] = value.get(i, 0).asDouble();
          molecule.setData("PES energy values", pesEnergyValues);
        }
      }
    }
    */
  }

  return true;
}

bool CjsonFormat::readVibrations(Value &root, Molecule &molecule)
{
  // Check for vibrational data.
  Value vibrations = root["vibrations"];

  if (!(testEmpty(vibrations, "vibrations") ||
        testIsNotObject(vibrations, "vibrations"))) {

    Value value = vibrations["frequencies"];
    if (!value.empty() && value.isArray()) {
      Array<double> frequencies;

      Index frequencyCount = static_cast<Index>(value.size());
      for (Index i = 0; i < frequencyCount; ++i)
        frequencies.push_back(value.get(i, 0).asDouble());

      molecule.setVibrationFrequencies(frequencies);
    }

    /* Not integrated, variant doesn't support templated Array container
    value = vibrations["vibration symmetry"];
    if (!value.empty() && value.isArray()) {
      Array<string> symmetries;

      Index symmetryCount = static_cast<Index>(value.size());
      for (Index i = 0; i < symmetryCount; ++i)
        symmetries.push_back(value.get(i, 0).asString());

      molecule.setData("vibration symmetry", symmetries);
    }
    */

    //Assumption: chose the vibir attribute over the vibraman attribute
    value = vibrations["intensities"]["IR"];
    if (!value.empty() && value.isArray()) {
      Array<double> intensities;

      Index intensityCount = static_cast<Index>(value.size());
      for (Index i = 0; i < intensityCount; ++i)
        intensities.push_back(value.get(i, 0).asDouble());

      molecule.setVibrationIntensities(intensities);
    }

    Value displacement = vibrations["displacement"];
    if (!displacement.empty() && displacement.isArray()) {
      Array<Array<Vector3> > Lx;

      for (Json::ArrayIndex i = 0; i < displacement.size(); ++i) {
        value = displacement.get(i, 0);
        if (!value.empty() && value.isArray()) {
          Array<Vector3> modeLx;
          modeLx.resize(value.size());
          for (Json::ArrayIndex j = 0; j < value.size(); ++j) {
            Value cartesianDisp = value.get(j, 0);
            for (int k = 0; k < 3; ++k) {
              modeLx[j][k] = cartesianDisp.get(k, 0).asDouble();
            }
          }
          Lx.push_back(modeLx);
        }
      }
      molecule.setVibrationLx(Lx);
    }
  }
  return true;
}

bool CjsonFormat::readBonds(Value &root, Molecule &molecule)
{
  // Now for the bonding data.
  Value bonds = root["bonds"];
  if (!bonds.empty()) {
    Value value = bonds["connections"];
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

bool CjsonFormat::readTransitions(Value &root, Molecule &)
{
  //Check for transitions data
  Value transitions = root["transitions"];

  if (!(testEmpty(transitions, "transitions") ||
        testIsNotObject(transitions, "transitions"))) {
    // Value value;

    /* Not integrated, variant doesn't support raw C-style arrays
    if (transitions.isMember("electronic transitions")) {
      value = transitions["electronic transitions"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        double *electronicTransitions = new double[targetCount];
        for (int i = 0; i < targetCount; ++i)
          electronicTransitions[i] = value.get(i, 0).asDouble();
        molecule.setData("electronic transitions", electronicTransitions);
      }
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    if (transitions.isMember("oscillator strength")) {
      value = transitions["oscillator strength"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        double *oscillatorStrength = new double[targetCount];
        for (int i = 0; i < targetCount; ++i)
          oscillatorStrength[i] = value.get(i, 0).asDouble();
        molecule.setData("oscillator strength", oscillatorStrength);
      }
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    if (transitions.isMember("rotatory strength")) {
      value = transitions["rotatory strength"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        double *rotatoryStrength = new double[targetCount];
        for (int i = 0; i < targetCount; ++i)
          rotatoryStrength[i] = value.get(i, 0).asDouble();
        molecule.setData("rotatory strength", rotatoryStrength);
      }
    }
    */

    /* Not integrated, variant doesn't support raw C-style arrays
    if (transitions.isMember("symmetry")) {
      value = transitions["symmetry"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        string *transitionSymmetry = new string[targetCount];
        for (int i = 0; i < targetCount; ++i)
          transitionSymmetry[i] = value.get(i, 0).asString();
        molecule.setData("electronic transition symmetry", transitionSymmetry);
      }
    }
    */
  }

  return true;
}

bool CjsonFormat::readFragments(Value &root, Molecule &molecule)
{
  //Check for fragments data
  Value fragments = root["fragments"];

  if (!(testEmpty(fragments, "fragments") ||
        testIsNotObject(fragments, "fragments"))) {
    Value value;

    /* Not integrated, variant doesn't support raw C-style arrays
    if (fragments.isMember("fragment names")) {
      value = fragments["fragment names"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        string *fragmentNames = new string[targetCount];
        for (int i = 0; i < targetCount; ++i)
          fragmentNames[i] = value.get(i, 0).asString();
        molecule.setData("fragment names", fragmentNames);
      }
    }
    */

    value = fragments["atom indices"];
    if (!value.empty()) {
      int n = static_cast<int>(value.size());
      int L = static_cast<int>(value[0].size());
      MatrixX atomIndices(n,L);
      Value indicesArray;
      for (int i = 0; i < n; ++i) {
        indicesArray = value[i];
        for (int j =0; j < L ; j++) {
          atomIndices(i, j) = indicesArray.get(j, 0).asDouble();
        }
      }
      molecule.setData("fragment atom indices", atomIndices);
    }

    /* Not integrated, variant doesn't support raw C-style arrays
    if (fragments.isMember("orbital  names")) {
      value = fragments["orbital  names"];

      if (!value.empty() && !value.isArray()) {
        int targetCount = static_cast<int>(value.size());
        string *orbitalNames = new string[targetCount];
        for (int i = 0; i < targetCount; ++i)
          orbitalNames[i] = value.get(i, 0).asString();
        molecule.setData("fragment orbital  names", orbitalNames);
      }
    }
    */

    value = fragments["orbital overlap"];
    if (!value.empty()) {
      int n = static_cast<int>(value.size());
      int L = static_cast<int>(value[0].size());
      MatrixX overlapIndices(n, L);
      Value indicesArray;
      for (int i = 0; i < n; ++i) {
        indicesArray = value[i];
        for (int j =0; j < L ; j++) {
          overlapIndices(i, j) = indicesArray.get(j, 0).asDouble();
        }
      }
      molecule.setData("fragment orbital overlap", overlapIndices);
    }
  }

  return true;
}

} // end Io namespace
} // end Avogadro namespace
