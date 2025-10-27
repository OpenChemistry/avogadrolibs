/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cjsonformat.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/layermanager.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <nlohmann/json.hpp>

#include <iomanip>
#include <iostream>

using json = nlohmann::json;

namespace Avogadro::Io {

using std::string;
using std::vector;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Cube;
using Core::GaussianSet;
using Core::LayerData;
using Core::LayerManager;
using Core::Molecule;
using Core::Residue;
using Core::Variant;

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
    for (const auto& v : j) {
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
    for (const auto& v : j) {
      if (!v.is_boolean()) {
        return false;
      }
    }
    return true;
  }
  return false;
}

json eigenColToJson(const MatrixX& matrix, int column)
{
  json j;
  j = json::array();
  for (Eigen::Index i = 0; i < matrix.rows(); ++i) {
    j.push_back(matrix(i, column));
  }
  return j;
}

bool CjsonFormat::read(std::istream& file, Molecule& molecule)
{
  return deserialize(file, molecule, true);
}

bool CjsonFormat::deserialize(std::istream& file, Molecule& molecule,
                              bool isJson)
{
  json jsonRoot;
  // could throw parse errors
  try {
    if (isJson)
      jsonRoot = json::parse(file, nullptr, false);
    else // msgpack
      jsonRoot = json::from_msgpack(file);
  } catch (json::parse_error& e) {
    appendError("Error reading CJSON file: " + string(e.what()));
    return false;
  } catch (json::type_error& e) {
    appendError("Error reading CJSON file: " + string(e.what()));
    return false;
  }

  if (jsonRoot.is_discarded()) {
    appendError("Error reading CJSON file.");
    return false;
  }

  if (!jsonRoot.is_object()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  auto jsonValue = jsonRoot.find("chemicalJson");
  if (jsonValue == jsonRoot.end())
    jsonValue = jsonRoot.find("chemical json");
  if (jsonValue == jsonRoot.end()) {
    appendError("Error: no \"chemical json\" key found.");
    return false;
  }
  if (*jsonValue != 0 && *jsonValue != 1) {
    appendError("Warning: chemical json version is not 0 or 1.");
    return false;
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

  if (!atoms.contains("elements")) {
    appendError("The 'atoms' key does not contain an 'elements' key.");
    return false;
  }

  if (atoms.contains("elements") && !atoms["elements"].is_object()) {
    appendError("The 'elements' key does not contain an object.");
    return false;
  }

  json elements = atoms["elements"];
  if (!elements.contains("number")) {
    appendError("The 'elements' key does not contain a 'number' key.");
    return false;
  }

  json atomicNumbers = elements["number"];
  // This represents our minimal spec for a molecule - atoms that have an
  // atomic number.
  if (isNumericArray(atomicNumbers) && atomicNumbers.size() > 0) {
    for (auto& atomicNumber : atomicNumbers) {
      if (!atomicNumber.is_number_integer() || atomicNumber < 0 ||
          atomicNumber >= Core::element_count) {
        appendError("Error: atomic number is invalid.");
        return false;
      }
      molecule.addAtom(atomicNumber);
    }
  } else {
    // we're done, actually - this is an empty file
    return true;
  }
  Index atomCount = molecule.atomCount();

  if (atoms.contains("coords") && atoms["coords"].is_object()) {
    if (atoms["coords"].contains("3d") && atoms["coords"]["3d"].is_array()) {
      json atomicCoords = atoms["coords"]["3d"];
      if (isNumericArray(atomicCoords) &&
          atomicCoords.size() == 3 * atomCount) {
        for (Index i = 0; i < atomCount; ++i) {
          auto a = molecule.atom(i);
          a.setPosition3d(Vector3(atomicCoords[3 * i], atomicCoords[3 * i + 1],
                                  atomicCoords[3 * i + 2]));
        }
      }
    }

    if (atoms["coords"].contains("3dSets")) {
      // Check for coordinate sets, and read them in if found, e.g.
      // trajectories.
      json coordSets = atoms["coords"]["3dSets"];
      if (coordSets.is_array() && coordSets.size()) {
        for (unsigned int i = 0; i < coordSets.size(); ++i) {
          Array<Vector3> setArray;
          json set = coordSets[i];
          if (isNumericArray(set)) {
            for (unsigned int j = 0; j < set.size() / 3; ++j) {
              setArray.push_back(
                Vector3(set[3 * j], set[3 * j + 1], set[3 * j + 2]));
            }
            molecule.setCoordinate3d(setArray, i);
          }
        }
        // Make sure the first step is active once we are done loading the sets.
        molecule.setCoordinate3d(0);
      }
    }
  }

  // Array of vector3 for forces if available
  if (atoms.contains("forces")) {
    json forces = atoms["forces"];
    if (isNumericArray(forces) && forces.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        auto a = molecule.atom(i);
        a.setForceVector(
          Vector3(forces[3 * i], forces[3 * i + 1], forces[3 * i + 2]));
      }
    }
  }

  // labels
  if (atoms.contains("labels")) {
    json labels = atoms["labels"];
    if (labels.is_array() && labels.size() == atomCount) {
      for (size_t i = 0; i < atomCount; ++i) {
        molecule.setAtomLabel(i, labels[i]);
      }
    }
  }

  // formal charges
  if (atoms.contains("formalCharges")) {
    json formalCharges = atoms["formalCharges"];
    if (formalCharges.is_array() && formalCharges.size() == atomCount) {
      for (size_t i = 0; i < atomCount; ++i) {
        molecule.atom(i).setFormalCharge(formalCharges[i]);
      }
    }
  }

  // Read in colors if they are present.
  if (atoms.contains("colors")) {
    json colors = atoms["colors"];
    if (colors.is_array() && colors.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        Vector3ub color(colors[3 * i], colors[3 * i + 1], colors[3 * i + 2]);
        molecule.setColor(i, color);
      }
    }
  }

  if (atoms.contains("properties")) {
    json atomProperties = atoms["properties"];
    if (atomProperties.is_object()) {
      for (auto& property : atomProperties.items()) {
        if (property.value().is_array()) {
          // TODO: handle atom properties
        }
      }
    }
  }

  // Selection is optional, but if present should be loaded.
  if (atoms.contains("selected")) {
    json selection = atoms["selected"];
    if (isBooleanArray(selection) && selection.size() == atomCount)
      for (Index i = 0; i < atomCount; ++i)
        molecule.setAtomSelected(i, selection[i]);
    else if (isNumericArray(selection) && selection.size() == atomCount)
      for (Index i = 0; i < atomCount; ++i)
        molecule.setAtomSelected(i, selection[i] != 0);
  }

  if (atoms.contains("frozen")) {
    json frozen = atoms["frozen"];
    if (frozen.is_array() && frozen.size() == atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        bool freeze = false;
        if (frozen[i].is_number())
          freeze = (frozen[i] != 0);
        else if (frozen[i].is_boolean())
          freeze = frozen[i];
        molecule.setFrozenAtom(i, freeze);
      }
    } // might also be a 3xN array for per-axis freezing
    else if (frozen.is_array() && frozen.size() == 3 * atomCount) {
      for (Index i = 0; i < atomCount; ++i) {
        bool freeze;
        if (frozen[3 * i].is_number())
          freeze = (frozen[3 * i] != 0);
        else if (frozen[3 * i].is_boolean())
          freeze = frozen[3 * i];
        molecule.setFrozenAtomAxis(i, 0, freeze);

        if (frozen[3 * i + 1].is_number())
          freeze = (frozen[3 * i + 1] != 0);
        else if (frozen[3 * i + 1].is_boolean())
          freeze = frozen[3 * i + 1];
        molecule.setFrozenAtomAxis(i, 1, freeze);

        if (frozen[3 * i + 2].is_number())
          freeze = (frozen[3 * i + 2] != 0);
        else if (frozen[3 * i + 2].is_boolean())
          freeze = frozen[3 * i + 2];
        molecule.setFrozenAtomAxis(i, 2, freeze);
      }
    }
  }

  if (atoms.find("layer") != atoms.end()) {
    json layerJson = atoms["layer"];
    if (isNumericArray(layerJson)) {
      auto& layer = LayerManager::getMoleculeInfo(&molecule)->layer;
      for (Index i = 0; i < atomCount && i < layerJson.size(); ++i) {
        while (layerJson[i] > layer.maxLayer()) {
          layer.addLayer();
        }
        layer.addAtom(layerJson[i], i);
      }
    }
  }

  // Bonds are optional, but if present should be loaded.
  if (jsonRoot.contains("bonds")) {
    json bonds = jsonRoot["bonds"];
    if (bonds.is_object() && isNumericArray(bonds["connections"]["index"])) {
      json connections = bonds["connections"]["index"];
      for (unsigned int i = 0; i < connections.size() / 2; ++i) {
        Index atom1 = static_cast<Index>(connections[2 * i]);
        Index atom2 = static_cast<Index>(connections[2 * i + 1]);
        if (atom1 < atomCount && atom2 < atomCount &&
            atom1 != atom2) { // avoid self-bonds
          molecule.addBond(atom1, atom2, 1);
        }
      }
      if (bonds.contains("order")) {
        json order = bonds["order"];
        if (isNumericArray(order)) {
          for (unsigned int i = 0; i < molecule.bondCount() && i < order.size();
               ++i) {
            molecule.bond(i).setOrder(static_cast<int>(order[i]));
          }
        }
      }

      // are there bond labels?
      if (bonds.contains("labels")) {
        json bondLabels = bonds["labels"];
        if (bondLabels.is_array()) {
          for (unsigned int i = 0;
               i < molecule.bondCount() && i < bondLabels.size(); ++i) {
            molecule.setBondLabel(i, bondLabels[i]);
          }
        }
      }

      if (bonds.contains("properties")) {
        json bondProperties = bonds["properties"];
        if (bondProperties.is_object()) {
          for (auto& property : bondProperties.items()) {
            if (property.value().is_array()) {
              // TODO: handle bond properties
            }
          }
        }
      }
    }
  }

  // residues are optional, but should be loaded
  if (jsonRoot.contains("residues")) {
    json residues = jsonRoot["residues"];
    if (residues.is_array()) {
      for (auto residue : residues) {
        if (!residue.is_object())
          continue; // malformed

        auto name = residue["name"].get<std::string>();
        auto id = static_cast<Index>(residue["id"]);
        auto chainId = residue["chainId"].get<char>();
        Residue newResidue(name, id, chainId);

        json hetero = residue["hetero"];
        if (hetero == true)
          newResidue.setHeterogen(true);

        int secStruct = residue.value("secStruct", -1);
        if (secStruct != -1)
          newResidue.setSecondaryStructure(
            static_cast<Avogadro::Core::Residue::SecondaryStructure>(
              secStruct));

        json atomsResidue = residue["atoms"];
        if (atomsResidue.is_object()) {
          for (auto& item : atomsResidue.items()) {
            if (item.value() < molecule.atomCount()) {
              const Atom& atom = molecule.atom(item.value());
              newResidue.addResidueAtom(item.key(), atom);
            }
          }
        }
        json color = residue["color"];
        if (color.is_array() && color.size() == 3) {
          Vector3ub col = Vector3ub(color[0], color[1], color[2]);
          newResidue.setColor(col);
        }

        molecule.addResidue(newResidue);
      }
    }
  }

  if (jsonRoot.contains("unitCell") || jsonRoot.contains("unit cell")) {
    json unitCell = jsonRoot["unitCell"];
    if (!unitCell.is_object())
      unitCell = jsonRoot["unit cell"];

    if (unitCell.is_object()) {
      Core::UnitCell* unitCellObject = nullptr;

      // read in cell vectors in preference to a, b, c parameters
      json cellVectors = unitCell["cellVectors"];
      if (cellVectors.is_array() && cellVectors.size() == 9 &&
          isNumericArray(cellVectors)) {
        Vector3 aVector(cellVectors[0], cellVectors[1], cellVectors[2]);
        Vector3 bVector(cellVectors[3], cellVectors[4], cellVectors[5]);
        Vector3 cVector(cellVectors[6], cellVectors[7], cellVectors[8]);
        unitCellObject = new Core::UnitCell(aVector, bVector, cVector);
        if (!unitCellObject->isRegular()) {
          appendError("cellVectors are not linear independent");
          delete unitCellObject;
          return false;
        }
      } else if (unitCell["a"].is_number() && unitCell["b"].is_number() &&
                 unitCell["c"].is_number() && unitCell["alpha"].is_number() &&
                 unitCell["beta"].is_number() &&
                 unitCell["gamma"].is_number()) {
        Real a = static_cast<Real>(unitCell["a"]);
        Real b = static_cast<Real>(unitCell["b"]);
        Real c = static_cast<Real>(unitCell["c"]);
        Real alpha = static_cast<Real>(unitCell["alpha"]) * DEG_TO_RAD;
        Real beta = static_cast<Real>(unitCell["beta"]) * DEG_TO_RAD;
        Real gamma = static_cast<Real>(unitCell["gamma"]) * DEG_TO_RAD;
        unitCellObject = new Core::UnitCell(a, b, c, alpha, beta, gamma);
        if (!unitCellObject->isRegular()) {
          appendError(
            "cell parameters do not give linear-independent lattice vectors");
          delete unitCellObject;
          return false;
        }
      }
      if (unitCellObject != nullptr)
        molecule.setUnitCell(unitCellObject);

      // check for Hall number if present
      if (unitCell["hallNumber"].is_number()) {
        auto hallNumber = static_cast<int>(unitCell["hallNumber"]);
        if (hallNumber > 0 && hallNumber < 531)
          molecule.setHallNumber(hallNumber);
      } else if (unitCell["spaceGroup"].is_string()) {
        auto hallNumber = Core::SpaceGroups::hallNumber(unitCell["spaceGroup"]);
        if (hallNumber != 0)
          molecule.setHallNumber(hallNumber);
      }
    }
  }

  if (atoms["coords"].contains("3dFractional") ||
      atoms["coords"].contains("3d fractional")) {
    json fractional = atoms["coords"]["3dFractional"];
    if (!fractional.is_array())
      fractional = atoms["coords"]["3d fractional"];
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
  }

  // Basis set is optional, if present read it in.
  if (jsonRoot.contains("basisSet")) {
    json basisSet = jsonRoot["basisSet"];
    if (basisSet.is_object()) {
      auto* basis = new GaussianSet;
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
          case 3:
            type = GaussianSet::F;
            break;
          case -3:
            type = GaussianSet::F7;
            break;
          case 4:
            type = GaussianSet::G;
            break;
          case -4:
            type = GaussianSet::G9;
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
        json occupations = orbitals["occupations"];
        if (isNumericArray(occupations)) {
          std::vector<unsigned char> occs;
          for (auto& occupation : occupations)
            occs.push_back(static_cast<unsigned char>(occupation));
          basis->setMolecularOrbitalOccupancy(occupations);
        }
        json energies = orbitals["energies"];
        if (isNumericArray(energies)) {
          std::vector<double> energyArray;
          for (auto& energie : energies)
            energyArray.push_back(static_cast<double>(energie));
          basis->setMolecularOrbitalEnergy(energyArray);
        }
        json numbers = orbitals["numbers"];
        if (isNumericArray(numbers)) {
          std::vector<unsigned int> numArray;
          for (auto& number : numbers)
            numArray.push_back(static_cast<unsigned int>(number));
          basis->setMolecularOrbitalNumber(numArray);
        }
        json symmetryLabels = orbitals["symmetries"];
        if (symmetryLabels.is_array()) {
          std::vector<std::string> symArray;
          for (auto& sym : symmetryLabels)
            symArray.push_back(sym);
          basis->setSymmetryLabels(symArray);
        }
        json moCoefficients = orbitals["moCoefficients"];
        json moCoefficientsA = orbitals["alphaCoefficients"];
        json moCoefficientsB = orbitals["betaCoefficients"];
        bool openShell = false;
        if (isNumericArray(moCoefficients)) {
          std::vector<double> coeffs;
          for (auto& moCoefficient : moCoefficients)
            coeffs.push_back(static_cast<double>(moCoefficient));
          basis->setMolecularOrbitals(coeffs);
        } else if (isNumericArray(moCoefficientsA) &&
                   isNumericArray(moCoefficientsB)) {
          std::vector<double> coeffsA;
          for (auto& i : moCoefficientsA)
            coeffsA.push_back(static_cast<double>(i));
          std::vector<double> coeffsB;
          for (auto& i : moCoefficientsB)
            coeffsB.push_back(static_cast<double>(i));
          basis->setMolecularOrbitals(coeffsA, BasisSet::Alpha);
          basis->setMolecularOrbitals(coeffsB, BasisSet::Beta);
          openShell = true;
        } else {
          std::cout << "No orbital cofficients found!" << std::endl;
        }
        // Check for orbital coefficient sets, these are paired with coordinates
        // when they exist, but have constant basis set, atom types, etc.
        if (orbitals["sets"].is_array() && orbitals["sets"].size()) {
          json orbSets = orbitals["sets"];
          for (unsigned int idx = 0; idx < orbSets.size(); ++idx) {
            moCoefficients = orbSets[idx]["moCoefficients"];
            moCoefficientsA = orbSets[idx]["alphaCoefficients"];
            moCoefficientsB = orbSets[idx]["betaCoefficients"];
            if (isNumericArray(moCoefficients)) {
              std::vector<double> coeffs;
              for (auto& moCoefficient : moCoefficients)
                coeffs.push_back(static_cast<double>(moCoefficient));
              basis->setMolecularOrbitals(coeffs, BasisSet::Paired, idx);
            } else if (isNumericArray(moCoefficientsA) &&
                       isNumericArray(moCoefficientsB)) {
              std::vector<double> coeffsA;
              for (auto& i : moCoefficientsA)
                coeffsA.push_back(static_cast<double>(i));
              std::vector<double> coeffsB;
              for (auto& i : moCoefficientsB)
                coeffsB.push_back(static_cast<double>(i));
              basis->setMolecularOrbitals(coeffsA, BasisSet::Alpha, idx);
              basis->setMolecularOrbitals(coeffsB, BasisSet::Beta, idx);
              openShell = true;
            }
          }
          // Set the first step as active.
          basis->setActiveSetStep(0);
        }
        if (openShell) {
          // look for alpha and beta orbital energies
          json energiesA = orbitals["alphaEnergies"];
          json energiesB = orbitals["betaEnergies"];
          // check if they are numeric arrays
          if (isNumericArray(energiesA) && isNumericArray(energiesB)) {
            std::vector<double> moEnergiesA;
            for (auto& i : energiesA)
              moEnergiesA.push_back(static_cast<double>(i));
            std::vector<double> moEnergiesB;
            for (auto& i : energiesB)
              moEnergiesB.push_back(static_cast<double>(i));
            basis->setMolecularOrbitalEnergy(moEnergiesA, BasisSet::Alpha);
            basis->setMolecularOrbitalEnergy(moEnergiesB, BasisSet::Beta);

            // look for alpha and beta orbital occupations
            json occupationsA = orbitals["alphaOccupations"];
            json occupationsB = orbitals["betaOccupations"];
            // check if they are numeric arrays
            if (isNumericArray(occupationsA) && isNumericArray(occupationsB)) {
              std::vector<unsigned char> moOccupationsA;
              for (auto& i : occupationsA)
                moOccupationsA.push_back(static_cast<unsigned char>(i));
              std::vector<unsigned char> moOccupationsB;
              for (auto& i : occupationsB)
                moOccupationsB.push_back(static_cast<unsigned char>(i));
              basis->setMolecularOrbitalOccupancy(moOccupationsA,
                                                  BasisSet::Alpha);
              basis->setMolecularOrbitalOccupancy(moOccupationsB,
                                                  BasisSet::Beta);
            }
          }
        }
      }
      molecule.setBasisSet(basis);
    }
  }

  // See if there is any vibration data, load it if so.
  json vibrations = jsonRoot["vibrations"];
  if (vibrations.is_object()) {
    json frequencies = vibrations["frequencies"];
    if (isNumericArray(frequencies)) {
      Array<double> freqs;
      for (auto& frequencie : frequencies) {
        freqs.push_back(static_cast<double>(frequencie));
      }
      molecule.setVibrationFrequencies(freqs);
    }
    json intensities = vibrations["intensities"];
    if (isNumericArray(intensities)) {
      Array<double> intens;
      for (auto& intensitie : intensities) {
        intens.push_back(static_cast<double>(intensitie));
      }
      molecule.setVibrationIRIntensities(intens);
    }
    json raman = vibrations["ramanIntensities"];
    if (isNumericArray(raman)) {
      Array<double> intens;
      for (auto& i : raman) {
        intens.push_back(static_cast<double>(i));
      }
      molecule.setVibrationRamanIntensities(intens);
    }
    json displacements = vibrations["eigenVectors"];
    if (displacements.is_array()) {
      Array<Array<Vector3>> disps;
      for (auto arr : displacements) {
        if (isNumericArray(arr)) {
          Array<Vector3> mode;
          mode.resize(arr.size() / 3);
          double* ptr = &mode[0][0];
          for (auto& j : arr) {
            *(ptr++) = static_cast<double>(j);
          }
          disps.push_back(mode);
        }
      }
      molecule.setVibrationLx(disps);
    }
  }

  // check for spectra data
  json spectra = jsonRoot["spectra"];
  if (spectra.is_object()) {
    // electronic
    json electronic = spectra["electronic"];
    if (electronic.is_object()) {
      // check to see "energies" and "intensities"
      json energies = electronic["energies"];
      json intensities = electronic["intensities"];
      // make sure they are both numeric arrays
      if (isNumericArray(energies) && isNumericArray(intensities)) {
        // make sure they are the same size
        if (energies.size() == intensities.size()) {
          // create the matrix
          MatrixX electronicData(energies.size(), 2);
          // copy the data
          for (std::size_t i = 0; i < energies.size(); ++i) {
            electronicData(i, 0) = energies[i];
            electronicData(i, 1) = intensities[i];
          }
          // set the data
          molecule.setSpectra("Electronic", electronicData);
        }
      }
      // check if there's CD data for "rotation"
      json rotation = electronic["rotation"];
      if (isNumericArray(rotation) && rotation.size() == energies.size()) {
        MatrixX rotationData(rotation.size(), 2);
        for (std::size_t i = 0; i < rotation.size(); ++i) {
          rotationData(i, 0) = energies[i];
          rotationData(i, 1) = rotation[i];
        }
        molecule.setSpectra("CircularDichroism", rotationData);
      }
    }

    // nmr
    json nmr = spectra["nmr"];
    if (nmr.is_object()) {
      // chemical shifts
      json chemicalShifts = nmr["shifts"];
      if (isNumericArray(chemicalShifts)) {
        MatrixX chemicalShiftData(chemicalShifts.size(), 2);
        for (std::size_t i = 0; i < chemicalShifts.size(); ++i) {
          chemicalShiftData(i, 0) = static_cast<double>(chemicalShifts[i]);
          chemicalShiftData(i, 1) = 1.0;
        }
        molecule.setSpectra("NMR", chemicalShiftData);
      }
    }
  }

  // constraints
  if (jsonRoot.find("constraints") != jsonRoot.end()) {
    json constraints = jsonRoot["constraints"];
    if (constraints.is_array()) {
      for (auto& constraint : constraints) {
        if (isNumericArray(constraint)) {
          // value, atom1, atom2, atom3, atom4
          if (constraint.size() == 3) { // bond
            molecule.addConstraint(constraint[0], constraint[1], constraint[2]);
          } else if (constraint.size() == 4) { // angle
            molecule.addConstraint(constraint[0], constraint[1], constraint[2],
                                   constraint[3]);
          } else if (constraint.size() == 5) { // torsion
            molecule.addConstraint(constraint[0], constraint[1], constraint[2],
                                   constraint[3], constraint[4]);
          }
        }
      }
    }
  }

  // properties
  if (jsonRoot.find("properties") != jsonRoot.end()) {
    json properties = jsonRoot["properties"];
    if (properties.is_object()) {
      if (properties.find("totalCharge") != properties.end()) {
        molecule.setData("totalCharge",
                         static_cast<int>(properties["totalCharge"]));
      }
      if (properties.find("totalSpinMultiplicity") != properties.end()) {
        molecule.setData("totalSpinMultiplicity",
                         static_cast<int>(properties["totalSpinMultiplicity"]));
      }
      if (properties.find("dipoleMoment") != properties.end()) {
        // read the numeric array
        json dipole = properties["dipoleMoment"];
        if (isNumericArray(dipole) && dipole.size() == 3) {
          Core::Variant dipoleMoment(dipole[0], dipole[1], dipole[2]);
          molecule.setData("dipoleMoment", dipoleMoment);
        }
      }
      // iterate through everything else
      for (auto& element : properties.items()) {
        if (element.key() == "totalCharge" ||
            element.key() == "totalSpinMultiplicity" ||
            element.key() == "dipoleMoment") {
          continue;
        }
        if (element.value().type() == json::value_t::array) {
          // check if it is a numeric array to go into Eigen::MatrixXd
          json j = element.value(); // convenience
          std::size_t rows = j.size();
          MatrixX matrix;
          matrix.resize(rows, 1); // default to 1 columns
          bool isNumeric = true;

          for (std::size_t row = 0; row < j.size(); ++row) {
            const auto& jrow = j.at(row);
            // check to see if we have a simple vector or a matrix
            if (jrow.type() == json::value_t::array) {
              matrix.conservativeResize(rows, jrow.size());
              for (std::size_t col = 0; col < jrow.size(); ++col) {
                const auto& value = jrow.at(col);
                if (value.type() == json::value_t::number_float ||
                    value.type() == json::value_t::number_integer ||
                    value.type() == json::value_t::number_unsigned)
                  matrix(row, col) = value.get<double>();
                else {
                  isNumeric = false;
                  break;
                }
              }
            } else if (jrow.type() == json::value_t::number_float ||
                       jrow.type() == json::value_t::number_integer ||
                       jrow.type() == json::value_t::number_unsigned) {
              // just a row vector
              matrix(row, 0) = jrow.get<double>();
            } else {
              isNumeric = false;
              break;
            }
          }
          if (isNumeric)
            molecule.setData(element.key(), matrix);
          // TODO: add support for non-numeric arrays
          // std::cout << " property: " << element.key() << " = " << matrix
          //           << " size " << matrix.rows() << 'x' << matrix.cols()
          //          << std::endl;
        } else if (element.value().type() == json::value_t::number_float) {
          molecule.setData(element.key(), element.value().get<double>());
        } else if (element.value().type() == json::value_t::number_integer) {
          molecule.setData(element.key(), element.value().get<int>());
        } else if (element.value().type() == json::value_t::boolean) {
          molecule.setData(element.key(), element.value().get<bool>());
        } else if (element.value().type() == json::value_t::string) {
          molecule.setData(element.key(), element.value().get<std::string>());
        } else {
          std::cout << " cannot store property: " << element.key() << " = "
                    << element.value() << " type "
                    << element.value().type_name() << std::endl;
        }
      }
    }
  }

  // inputParameters are calculation metadata
  if (jsonRoot.find("inputParameters") != jsonRoot.end()) {
    json inputParameters = jsonRoot["inputParameters"];
    // add this as a string to the molecule data
    molecule.setData("inputParameters", inputParameters.dump());
  }

  // Partial charges are optional, but if present should be loaded.
  json partialCharges;
  if (atoms.contains("partialCharges")) {
    partialCharges = atoms["partialCharges"];
  }
  // some inconsistent files have it as part of the root
  if (jsonRoot.contains("partialCharges")) {
    partialCharges = jsonRoot["partialCharges"];
  }
  if (partialCharges.is_object()) {
    // keys are types, values are arrays of charges
    for (auto& kv : partialCharges.items()) {
      MatrixX charges(atomCount, 1);
      if (isNumericArray(kv.value()) && kv.value().size() == atomCount) {
        for (size_t i = 0; i < kv.value().size(); ++i) {
          charges(i, 0) = kv.value()[i];
        }
        molecule.setPartialCharges(kv.key(), charges);
      }
    }
  }

  // look for possible cube data
  if (jsonRoot.find("cube") != jsonRoot.end()) {
    json cubeObj = jsonRoot["cube"];
    // get the limits
    Vector3 min, max, delta;
    Vector3i points;
    json origin = cubeObj["origin"];
    json spacing = cubeObj["spacing"];
    json dimensions = cubeObj["dimensions"];
    json type = cubeObj["type"];

    if (isNumericArray(origin) && origin.size() == 3 &&
        isNumericArray(spacing) && spacing.size() == 3 &&
        isNumericArray(dimensions) && dimensions.size() == 3) {
      Cube* cube = molecule.addCube();

      // types
      if (type == "vdw")
        cube->setCubeType(Cube::VdW);
      else if (type == "solventAccessible")
        cube->setCubeType(Cube::SolventAccessible);
      else if (type == "solventExcluded")
        cube->setCubeType(Cube::SolventExcluded);
      else if (type == "esp")
        cube->setCubeType(Cube::ESP);
      else if (type == "electronDensity")
        cube->setCubeType(Cube::ElectronDensity);
      else if (type == "spinDensity")
        cube->setCubeType(Cube::SpinDensity);
      else if (type == "mo")
        cube->setCubeType(Cube::MO);
      else
        cube->setCubeType(Cube::FromFile);

      if (cubeObj.find("name") != cubeObj.end())
        cube->setName(cubeObj["name"]);

      min = Vector3(origin[0], origin[1], origin[2]);
      points = Vector3i(dimensions[0], dimensions[1], dimensions[2]);
      delta = Vector3(spacing[0], spacing[1], spacing[2]);
      max = Vector3(min[0] + (points[0] - 1) * delta[0],
                    min[1] + (points[1] - 1) * delta[1],
                    min[2] + (points[2] - 1) * delta[2]);

      cube->setLimits(min, max, points);
      // check the length of the scalar array
      unsigned int expectedSize = points[0] * points[1] * points[2];
      if (isNumericArray(cubeObj["scalars"]) &&
          cubeObj["scalars"].size() == expectedSize) {
        cube->setData(cubeObj["scalars"]);
      }
    }
  }

  if (jsonRoot.find("layer") != jsonRoot.end()) {
    auto names = LayerManager::getMoleculeInfo(&molecule);
    json visible = jsonRoot["layer"]["visible"];
    if (isBooleanArray(visible)) {
      for (const auto& v : visible) {
        names->visible.push_back(v);
      }
    }
    json locked = jsonRoot["layer"]["locked"];
    if (isBooleanArray(locked)) {
      for (const auto& l : locked) {
        names->locked.push_back(l);
      }
    }

    json enables = jsonRoot["layer"]["enable"];
    if (enables.is_object()) {
      for (const auto& enable : enables.items()) {
        if (isBooleanArray(enable.value())) {
          names->enable[enable.key()] = std::vector<bool>();
          for (const auto& e : enable.value()) {
            names->enable[enable.key()].push_back(e);
          }
        }
      }
    }

    json settings = jsonRoot["layer"]["settings"];
    if (settings.is_object()) {
      for (const auto& setting : settings.items()) {
        if (isBooleanArray(setting.value())) {
          names->settings[setting.key()] = Core::Array<LayerData*>();
          for (const auto& s : setting.value()) {
            names->settings[setting.key()].push_back(new LayerData(s));
          }
        }
      }
    }
  }

  return true;
}

bool CjsonFormat::write(std::ostream& file, const Molecule& molecule)
{
  return serialize(file, molecule, true);
}

bool CjsonFormat::serialize(std::ostream& file, const Molecule& molecule,
                            bool isJson)
{
  json opts;
  if (!options().empty())
    opts = json::parse(options(), nullptr, false);
  else
    opts = json::object();

  json root;

  root["chemicalJson"] = 1;

  if (opts.value("properties", true)) {
    if (molecule.data("name").type() == Variant::String)
      root["name"] = molecule.data("name").toString().c_str();
    if (molecule.data("inchi").type() == Variant::String)
      root["inchi"] = molecule.data("inchi").toString().c_str();
  }

  json properties;
  // these methods assume neutral singlet if not set
  // or approximate from formal charges and # of electrons
  properties["totalCharge"] = molecule.totalCharge();
  properties["totalSpinMultiplicity"] = molecule.totalSpinMultiplicity();
  // loop through all other properties
  const auto map = molecule.dataMap();
  for (const auto& element : map) {
    if (element.first == "name" || element.first == "inchi")
      continue;

    // check for "inputParameters" and handle it separately
    if (element.first == "inputParameters") {
      json inputParameters = json::parse(element.second.toString());
      root["inputParameters"] = inputParameters;
      continue;
    }

    // check if the key is atom.* or bond.* and handle it separately
    if (element.first.find("atom.") == 0 || element.first.find("bond.") == 0 ||
        element.first.find("residue.") == 0) {
      continue;
    }

    if (element.second.type() == Variant::String)
      properties[element.first] = element.second.toString().c_str();
    else if (element.second.type() == Variant::Double)
      properties[element.first] = element.second.toDouble();
    else if (element.second.type() == Variant::Float)
      properties[element.first] = element.second.toFloat();
    else if (element.second.type() == Variant::Int)
      properties[element.first] = element.second.toInt();
    else if (element.second.type() == Variant::Bool)
      properties[element.first] = element.second.toBool();
    else if (element.second.type() == Variant::Vector) {
      // e.g. dipole moment
      Vector3 v = element.second.toVector3();
      json vector;
      vector.push_back(v.x());
      vector.push_back(v.y());
      vector.push_back(v.z());
      properties[element.first] = vector;
    } else if (element.second.type() == Variant::Matrix) {
      MatrixX m = element.second.toMatrix();
      json matrix;
      for (int i = 0; i < m.rows(); ++i) {
        json row;
        for (int j = 0; j < m.cols(); ++j) {
          row.push_back(m(i, j));
        }
        matrix.push_back(row);
      }
      properties[element.first] = matrix;
    }
  }
  root["properties"] = properties;

  if (molecule.unitCell()) {
    json unitCell;
    unitCell["a"] = molecule.unitCell()->a();
    unitCell["b"] = molecule.unitCell()->b();
    unitCell["c"] = molecule.unitCell()->c();
    unitCell["alpha"] = molecule.unitCell()->alpha() * RAD_TO_DEG;
    unitCell["beta"] = molecule.unitCell()->beta() * RAD_TO_DEG;
    unitCell["gamma"] = molecule.unitCell()->gamma() * RAD_TO_DEG;

    json vectors;
    vectors.push_back(molecule.unitCell()->aVector().x());
    vectors.push_back(molecule.unitCell()->aVector().y());
    vectors.push_back(molecule.unitCell()->aVector().z());

    vectors.push_back(molecule.unitCell()->bVector().x());
    vectors.push_back(molecule.unitCell()->bVector().y());
    vectors.push_back(molecule.unitCell()->bVector().z());

    vectors.push_back(molecule.unitCell()->cVector().x());
    vectors.push_back(molecule.unitCell()->cVector().y());
    vectors.push_back(molecule.unitCell()->cVector().z());
    unitCell["cellVectors"] = vectors;

    // write the Hall number and space group
    unitCell["hallNumber"] = molecule.hallNumber();
    unitCell["spaceGroup"] =
      Core::SpaceGroups::international(molecule.hallNumber());

    root["unitCell"] = unitCell;
  }

  // check for spectra data
  // vibrations are separate
  if (molecule.spectraTypes().size() != 0) {
    json spectra, electronic, nmr;
    bool hasElectronic = false;
    for (const auto& type : molecule.spectraTypes()) {
      if (type == "Electronic") {
        hasElectronic = true;
        electronic["energies"] = eigenColToJson(molecule.spectra(type), 0);
        electronic["intensities"] = eigenColToJson(molecule.spectra(type), 1);
      } else if (type == "CircularDichroism") {
        electronic["rotation"] = eigenColToJson(molecule.spectra(type), 1);
      } else if (type == "NMR") {
        json data;
        data["shifts"] = eigenColToJson(molecule.spectra(type), 0);
        spectra["nmr"] = data;
      }
    }
    if (hasElectronic) {
      spectra["electronic"] = electronic;
    }
    root["spectra"] = spectra;
  }

  // Create a basis set/MO matrix we can round trip.
  if (molecule.basisSet() &&
      dynamic_cast<const GaussianSet*>(molecule.basisSet())) {
    json basis;
    auto gaussian = dynamic_cast<const GaussianSet*>(molecule.basisSet());

    // Map the shell types from enumeration to integer values.
    auto symmetry = gaussian->symmetry();
    json shellTypes;
    for (int i : symmetry) {
      switch (i) {
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
        case GaussianSet::F:
          shellTypes.push_back(3);
          break;
        case GaussianSet::F7:
          shellTypes.push_back(-3);
          break;
        case GaussianSet::G:
          shellTypes.push_back(4);
          break;
        case GaussianSet::G9:
          shellTypes.push_back(-4);
          break;
        default:
          // Something bad, put in a silly number...
          shellTypes.push_back(426942);
      }
    }
    basis["shellTypes"] = shellTypes;

    // This bit is slightly tricky, map from our index to primitives per
    // shell.
    if (gaussian->gtoIndices().size() && gaussian->atomIndices().size()) {
      auto gtoIndices = gaussian->gtoIndices();
      auto gtoA = gaussian->gtoA();
      json primitivesPerShell;
      for (size_t i = 0; i < gtoIndices.size() - 1; ++i)
        primitivesPerShell.push_back(gtoIndices[i + 1] - gtoIndices[i]);
      primitivesPerShell.push_back(gtoA.size() - gtoIndices.back());
      basis["primitivesPerShell"] = primitivesPerShell;

      auto atomIndices = gaussian->atomIndices();
      json shellToAtomMap;
      for (unsigned int& atomIndice : atomIndices)
        shellToAtomMap.push_back(atomIndice);
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

      // Write out the basis set if a valid one exists.
      root["basisSet"] = basis;
    }

    // Now get the MO matrix, potentially other things. Need to get a handle
    // on when we have just one (paired), or two (alpha and beta) to write.
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

    // Some energy, occupation, and number data potentially.
    auto energies = gaussian->moEnergy();
    if (energies.size() > 0) {
      json energyData;
      for (double& energie : energies) {
        energyData.push_back(energie);
      }

      auto betaEnergies = gaussian->moEnergy(BasisSet::Beta);
      if (betaEnergies.size() > 0) {
        json betaEnergyData;
        for (double& energie : betaEnergies) {
          betaEnergyData.push_back(energie);
        }
        root["orbitals"]["alphaEnergies"] = energyData;
        root["orbitals"]["betaEnergies"] = betaEnergyData;
      } else
        root["orbitals"]["energies"] = energyData;
    }
    auto occ = gaussian->moOccupancy();
    if (occ.size() > 0) {
      json occData;
      for (unsigned char& it : occ)
        occData.push_back(static_cast<int>(it));

      auto betaOcc = gaussian->moOccupancy(BasisSet::Beta);
      if (betaOcc.size() > 0) {
        json betaOccData;
        for (unsigned char& it : betaOcc)
          betaOccData.push_back(static_cast<int>(it));
        root["orbitals"]["alphaOccupations"] = occData;
        root["orbitals"]["betaOccupations"] = betaOccData;
      } else
        root["orbitals"]["occupations"] = occData;
    }
    auto num = gaussian->moNumber();
    if (num.size() > 0) {
      json numData;
      for (unsigned int& it : num)
        numData.push_back(it);
      root["orbitals"]["numbers"] = numData;
    }

    root["orbitals"]["electronCount"] = gaussian->electronCount();
  }

  // Write out any cubes that are present in the molecule.
  if (molecule.cubeCount() > 0) {
    json cubeObj;
    const Cube* cube = molecule.cube(0);
    // Get the origin, max, spacing, and dimensions to place in the object.
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

    // type
    switch (cube->cubeType()) {
      case Cube::VdW:
        cubeObj["type"] = "vdw";
        break;
      case Cube::SolventAccessible:
        cubeObj["type"] = "solventAccessible";
        break;
      case Cube::SolventExcluded:
        cubeObj["type"] = "solventExcluded";
        break;
      case Cube::ESP:
        cubeObj["type"] = "esp";
        break;
      case Cube::ElectronDensity:
        cubeObj["type"] = "electronDensity";
        break;
      case Cube::SpinDensity:
        cubeObj["type"] = "spinDensity";
        break;
      case Cube::MO:
        cubeObj["type"] = "mo";
        break;
      case Cube::FromFile:
      default:
        cubeObj["type"] = "fromFile";
        break;
    }

    // name
    cubeObj["name"] = cube->name();

    json cubeData;
    for (float it : *cube->data()) {
      cubeData.push_back(it);
    }
    cubeObj["scalars"] = cubeData;
    root["cube"] = cubeObj;
  }

  // Create and populate the atom arrays.
  if (molecule.atomCount()) {
    json atoms;
    json elements;
    json selected;
    json colors;

    Vector3ub color;
    bool hasCustomColors = molecule.colors().size() == molecule.atomCount();
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      elements.push_back(molecule.atom(i).atomicNumber());
      selected.push_back(molecule.atomSelected(i));

      color = molecule.color(i);
      colors.push_back(color.x());
      colors.push_back(color.y());
      colors.push_back(color.z());
    }
    atoms["elements"]["number"] = elements;
    if (!molecule.isSelectionEmpty())
      atoms["selected"] = selected;
    if (hasCustomColors)
      atoms["colors"] = colors;

    // check for frozen atoms
    json frozen;
    // any atoms frozen?
    bool anyFrozen = false;
    // any atoms with custom axis?
    // (i.e., we need to save the matrix)
    bool axisFrozen = false;
    Eigen::VectorXd frozenAtomMask = molecule.frozenAtomMask();
    for (Index i = 0; i < molecule.atomCount(); ++i) {
      if (molecule.frozenAtom(i)) {
        anyFrozen = true;
        frozen.push_back(1);
      } else {
        frozen.push_back(0);
      }

      // check for custom axis
      if (i * 3 + 2 < frozenAtomMask.size()) {
        Real sum = frozenAtomMask[3 * i] + frozenAtomMask[3 * i + 1] +
                   frozenAtomMask[3 * i + 2];
        // check if it's not all frozen or all unfrozen
        if (sum != 3.0 && sum != 0.0) {
          axisFrozen = true;
        }
      }
    }

    if (anyFrozen) {
      atoms["frozen"] = frozen;
    }
    if (axisFrozen) {
      // iterate through the mask as an array
      json frozenAtomMaskArray;
      for (Index i = 0; i < frozenAtomMask.size(); ++i) {
        frozenAtomMaskArray.push_back(frozenAtomMask[i]);
      }
      atoms["frozen"] = frozenAtomMaskArray;
    }

    // check for partial charges
    auto partialCharges = molecule.partialChargeTypes();
    if (!partialCharges.empty()) {
      // add them to the atoms object
      for (const auto& type : partialCharges) {
        MatrixX chargesMatrix = molecule.partialCharges(type);
        json charges;
        for (Index i = 0; i < molecule.atomCount(); ++i) {
          charges.push_back(chargesMatrix(i, 0));
        }
        atoms["partialCharges"][type] = charges;
      }
    }

    json coords;
    // 3d positions:
    if (molecule.atomPositions3d().size() == molecule.atomCount()) {
      // everything gets real-space Cartesians
      json coords3d;
      for (const auto& it : molecule.atomPositions3d()) {
        coords3d.push_back(it.x());
        coords3d.push_back(it.y());
        coords3d.push_back(it.z());
      }
      coords["3d"] = coords3d;

      // if the unit cell exists, also write fractional coords
      if (molecule.unitCell()) {
        json coordsFractional;
        Array<Vector3> fcoords;
        CrystalTools::fractionalCoordinates(
          *molecule.unitCell(), molecule.atomPositions3d(), fcoords);
        for (auto& fcoord : fcoords) {
          coordsFractional.push_back(fcoord.x());
          coordsFractional.push_back(fcoord.y());
          coordsFractional.push_back(fcoord.z());
        }
        coords["3dFractional"] = coordsFractional;
      }

      // if the molecule has multiple coordinate sets, write them out
      if (molecule.coordinate3dCount() > 1) {
        json coords3dSets;
        for (Index i = 0; i < molecule.coordinate3dCount(); ++i) {
          json coordsSet;
          const auto& positions = molecule.coordinate3d(i);
          for (const auto& it : positions) {
            coordsSet.push_back(it.x());
            coordsSet.push_back(it.y());
            coordsSet.push_back(it.z());
          }
          coords3dSets.push_back(coordsSet);
        }
        coords["3dSets"] = coords3dSets;
      }
    }

    // 2d positions:
    if (molecule.atomPositions2d().size() == molecule.atomCount()) {
      json coords2d;
      for (const auto& it : molecule.atomPositions2d()) {
        coords2d.push_back(it.x());
        coords2d.push_back(it.y());
      }
      coords["2d"] = coords2d;
    }
    atoms["coords"] = coords;

    // forces if present
    const auto forceVectors = molecule.forceVectors();
    if (forceVectors.size() == molecule.atomCount()) {
      json forces;
      for (const auto& force : forceVectors) {
        forces.push_back(force.x());
        forces.push_back(force.y());
        forces.push_back(force.z());
      }
      atoms["forces"] = forces;
    }

    // check for atom labels
    Array atomLabels = molecule.atomLabels();
    if (atomLabels.size() == molecule.atomCount()) {
      json labels;
      for (Index i = 0; i < molecule.atomCount(); ++i) {
        labels.push_back(atomLabels[i]);
      }
      atoms["labels"] = labels;
    }

    // formal charges
    json formalCharges;
    bool hasFormalCharges = false;
    for (size_t i = 0; i < molecule.atomCount(); ++i) {
      formalCharges.push_back(molecule.formalCharge(i));
      if (molecule.formalCharge(i) != 0)
        hasFormalCharges = true;
    }
    if (hasFormalCharges)
      atoms["formalCharges"] = formalCharges;

    auto layer = LayerManager::getMoleculeInfo(&molecule)->layer;
    if (layer.atomCount()) {
      json atomLayer;
      for (Index i = 0; i < layer.atomCount(); ++i) {
        atomLayer.push_back(layer.getLayerID(i));
      }
      atoms["layer"] = atomLayer;
    }

    // TODO check for atom properties
    root["atoms"] = atoms; // end atoms
  }

  // Create and populate the bond arrays.
  if (molecule.bondCount()) {
    json bonds;
    json connections;
    json order;
    for (Index i = 0; i < molecule.bondCount(); ++i) {
      Bond bond = molecule.bond(i);
      connections.push_back(bond.atom1().index());
      connections.push_back(bond.atom2().index());
      order.push_back(bond.order());
    }
    bonds["connections"]["index"] = connections;
    bonds["order"] = order;

    // check if there are bond labels
    Array bondLabels = molecule.bondLabels();
    if (bondLabels.size() == molecule.bondCount()) {
      json labels;
      for (Index i = 0; i < molecule.bondCount(); ++i) {
        labels.push_back(bondLabels[i]);
      }
      bonds["labels"] = labels;
    }

    // TODO check for bond properties
    root["bonds"] = bonds;
  }

  // Create and populate any residue arrays
  if (molecule.residues().size() > 0) {
    json residues; // array of objects
    for (auto residue : molecule.residues()) {
      json entry;
      entry["name"] = residue.residueName();
      entry["id"] = residue.residueId();
      entry["chainId"] = residue.chainId();
      entry["secStruct"] = residue.secondaryStructure();
      if (residue.isHeterogen())
        entry["hetero"] = true;

      json color;
      color.push_back(residue.color()[0]);
      color.push_back(residue.color()[1]);
      color.push_back(residue.color()[2]);
      entry["color"] = color;

      json atoms;
      for (const auto& item : residue.atomNameMap()) {
        // dictionary between names and atom Id
        atoms[item.first] = item.second.index();
      }
      entry["atoms"] = atoms;
      residues.push_back(entry);
    }
    root["residues"] = residues;

    // TODO check for residue properties
  }

  // any constraints?
  auto constraintList = molecule.constraints();
  if (!constraintList.empty()) {
    json constraints;
    for (auto& constraint : constraintList) {
      json constraintEntry;
      constraintEntry.push_back(constraint.value());
      constraintEntry.push_back(constraint.aIndex());
      constraintEntry.push_back(constraint.bIndex());
      if (constraint.cIndex() != MaxIndex) {
        constraintEntry.push_back(constraint.cIndex());
      }
      if (constraint.dIndex() != MaxIndex) {
        constraintEntry.push_back(constraint.dIndex());
      }
      constraints.push_back(constraintEntry);
    }
    root["constraints"] = constraints;
  }

  // If there is vibrational data write this out too.
  if (molecule.vibrationFrequencies().size() > 0 &&
      (molecule.vibrationFrequencies().size() ==
       molecule.vibrationIRIntensities().size())) {
    json vibrations;
    json modes;
    json freqs;
    json inten;
    json raman;
    json eigenVectors;
    for (size_t i = 0; i < molecule.vibrationFrequencies().size(); ++i) {
      modes.push_back(static_cast<unsigned int>(i) + 1);
      freqs.push_back(molecule.vibrationFrequencies()[i]);
      inten.push_back(molecule.vibrationIRIntensities()[i]);
      if (molecule.vibrationRamanIntensities().size() > i)
        raman.push_back(molecule.vibrationRamanIntensities()[i]);
      Core::Array<Vector3> atomDisplacements = molecule.vibrationLx(i);
      json eigenVector;
      for (auto pos : atomDisplacements) {
        eigenVector.push_back(pos[0]);
        eigenVector.push_back(pos[1]);
        eigenVector.push_back(pos[2]);
      }
      eigenVectors.push_back(eigenVector);
    }
    vibrations["modes"] = modes;
    vibrations["frequencies"] = freqs;
    vibrations["intensities"] = inten;
    if (molecule.vibrationRamanIntensities().size() > 0)
      vibrations["ramanIntensities"] = raman;
    vibrations["eigenVectors"] = eigenVectors;
    root["vibrations"] = vibrations;
  }

  auto names = LayerManager::getMoleculeInfo(&molecule);
  json layer;
  json visible;
  for (const bool v : names->visible) {
    visible.push_back(v);
  }
  layer["visible"] = visible;
  json locked;
  for (const bool l : names->locked) {
    locked.push_back(l);
  }
  layer["locked"] = locked;
  for (const auto& enables : names->enable) {
    json enable;
    for (const bool e : enables.second) {
      enable.push_back(e);
    }
    layer["enable"][enables.first] = enable;
  }

  for (const auto& settings : names->settings) {
    json setting;
    for (const auto& e : settings.second) {
      setting.push_back(e->serialize());
    }
    layer["settings"][settings.first] = setting;
  }
  root["layer"] = layer;

  if (isJson)
#ifndef NDEBUG
    // if debugging, pretty print
    file << std::setw(2) << root;
#else
    // release mode
    file << root;
#endif
  else { // write msgpack
    json::to_msgpack(root, file);
  }

  return true;
}

vector<std::string> CjsonFormat::fileExtensions() const
{
  vector<std::string> ext;
  ext.emplace_back("cjson");
  return ext;
}

vector<std::string> CjsonFormat::mimeTypes() const
{
  vector<std::string> mime;
  mime.emplace_back("chemical/x-cjson");
  return mime;
}

} // namespace Avogadro::Io
