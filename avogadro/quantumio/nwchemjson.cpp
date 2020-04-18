/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "nwchemjson.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/utilities.h>

#include <nlohmann/json.hpp>

#include <iostream>

namespace Avogadro {
namespace QuantumIO {

using std::cout;
using std::endl;
using std::string;
using std::vector;

using nlohmann::json;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Elements;
using Core::GaussianSet;
using Core::Molecule;
using Core::split;
using Core::Variant;

NWChemJson::NWChemJson() {}

NWChemJson::~NWChemJson() {}

bool NWChemJson::read(std::istream& file, Molecule& molecule)
{
  json root;
  try {
    file >> root;
  } catch (json::parse_error& e) {
    appendError("Error parsing JSON: " + string(e.what()));
    return false;
  }

  if (!root.is_object()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  if (root.find("simulation") == root.end()) {
    appendError("Error: no \"simulation\" key found.");
    return false;
  }

  json simulation = root["simulation"];

  if (simulation.find("calculations") == simulation.end() ||
      !simulation["calculations"].is_array()) {
    appendError("Error: no \"calculations\" array found.");
    return false;
  }

  // Scan the calculations array for calculationSetup.molecule objects.
  json calculations = simulation["calculations"];

  // Iterate through the objects in the array, and print out any molecules.
  json moleculeArray = json::array();
  json basisSetArray = json::array();
  json calculationVib;
  json molecularOrbitals;
  int numberOfElectrons = 0;
  string theory;
  string xcFunctional;
  for (size_t i = 0; i < calculations.size(); ++i) {
    json calcObj = calculations[i];
    if (calcObj.is_object()) {
      string calcType = calcObj.value("calculationType", "");
      // Store the last vibrational frequencies calculation object.
      if (calcType == "vibrationalModes")
        calculationVib = calcObj;
      json calcSetup = calcObj.value("calculationSetup", json());
      json calcMol = calcSetup.value("molecule", json());
      numberOfElectrons = calcSetup.value("numberOfElectrons", -1);
      if (calcSetup.count("exchangeCorrelationFunctional") &&
          calcSetup["exchangeCorrelationFunctional"].is_array() &&
          !calcSetup["exchangeCorrelationFunctional"].empty()) {
        json functional = calcSetup["exchangeCorrelationFunctional"][0];
        if (functional.is_object()) {
          xcFunctional = functional.value("xcName", "");
        }
        if (xcFunctional == "B3LYP Method XC Potential") {
          xcFunctional = "b3lyp";
        }
      }
      if (calcSetup.count("waveFunctionTheory")) {
        theory = calcSetup["waveFunctionTheory"].get<std::string>();
        if (theory == "Density Functional Theory") {
          theory = "dft";
        }
      }
      if (!calcMol.is_null() && calcMol.is_object())
        moleculeArray.push_back(calcMol);
      json basisSet = calcSetup.value("basisSet", json());
      if (!basisSet.is_null() && basisSet.is_object())
        basisSetArray.push_back(basisSet);

      json calcResults = calcObj.value("calculationResults", json());
      calcMol = calcResults.value("molecule", json());
      if (!calcMol.is_null() && calcMol.is_object())
        moleculeArray.push_back(calcMol);
      // There is currently one id for all, just get the last one we find.
      if (calcResults.count("molecularOrbitals") &&
          calcResults["molecularOrbitals"].is_object()) {
        molecularOrbitals = calcResults["molecularOrbitals"];
      }
    }
  }

  // For now, we are just grabbing the "last" molecule, and using that. This
  // needs more complex logic to step through the file and do it properly.
  json atoms;
  if (!moleculeArray.empty()) {
    json finalMol = moleculeArray.back();
    atoms = finalMol.value("atoms", json());
  }
  if (atoms.is_array()) {
    for (size_t i = 0; i < atoms.size(); ++i) {
      json jsonAtom = atoms[i];
      if (jsonAtom.is_null() || !jsonAtom.is_object())
        continue;
      Atom a = molecule.addAtom(
        static_cast<unsigned char>(jsonAtom.value("elementNumber", 0)));
      json pos = jsonAtom["cartesianCoordinates"]["value"];
      Vector3 position;
      if (pos.is_array() && pos.size() >= 3)
        position = Vector3(pos[0], pos[1], pos[2]);
      string units = jsonAtom["cartesianCoordinates"]["units"];
      if (units == "bohr")
        position *= BOHR_TO_ANGSTROM_D;
      a.setPosition3d(position);
    }
  }
  // Perceive bonds for the molecule.
  molecule.perceiveBondsSimple();

  // Add in the electronic structure information if available.
  if (molecularOrbitals.is_object() &&
      molecularOrbitals["atomicOrbitalDescriptions"].is_array()) {
    json basisSet;
    if (!basisSetArray.empty())
      basisSet = basisSetArray.back();
    json orbDesc = molecularOrbitals.value("atomicOrbitalDescriptions", json());

    // Figure out the mapping of basis set to molecular orbitals.
    Array<int> atomNumber;
    Array<string> atomSymbol;
    for (size_t i = 0; i < orbDesc.size(); ++i) {
      string desc = orbDesc[i];
      vector<string> parts = split(desc, ' ');
      assert(parts.size() == 3);
      int num = Core::lexicalCast<int>(parts[0]);
      if (atomNumber.size() > 0 && atomNumber.back() == num)
        continue;
      atomNumber.push_back(num);
      atomSymbol.push_back(parts[1]);
    }

    // Now create the structure, and expand out the orbitals.
    GaussianSet* basis = new GaussianSet;
    basis->setMolecule(&molecule);
    string basisSetName;
    for (size_t i = 0; i < atomSymbol.size(); ++i) {
      string symbol = atomSymbol[i];
      json basisFunctions = basisSet.value("basisFunctions", json());
      json currentFunction;
      for (size_t j = 0; j < basisFunctions.size(); ++j) {
        currentFunction = basisFunctions[j];

        string elementType;
        if (currentFunction.count("elementLabel"))
          elementType = currentFunction["elementLabel"].get<std::string>();
        else if (currentFunction.count("elementType"))
          elementType = currentFunction["elementType"].get<std::string>();

        if (elementType == symbol)
          break;

        currentFunction = json();
      }

      if (currentFunction.is_null())
        break;

      if (currentFunction.count("basisSetName")) {
        if (basisSetName.empty()) {
          basisSetName = currentFunction["basisSetName"].get<std::string>();
        } else if (basisSetName != currentFunction["basisSetName"]) {
          basisSetName = "Custom";
        }
      }

      json contraction = currentFunction.value("basisSetContraction", json());
      bool spherical =
        currentFunction.value("basisSetHarmonicType", "") == "spherical";
      for (size_t j = 0; j < contraction.size(); ++j) {
        json contractionShell = contraction[j];
        string shellType;
        if (contractionShell.count("basisSetShell"))
          shellType = contractionShell["basisSetShell"].get<std::string>();
        else if (contractionShell.count("basisSetShellType"))
          shellType = contractionShell["basisSetShellType"].get<std::string>();
        json exponent = contractionShell.value("basisSetExponent", json());
        json coefficient =
          contractionShell.value("basisSetCoefficient", json());
        assert(exponent.size() == coefficient.size());
        GaussianSet::orbital type = GaussianSet::UU;
        if (shellType == "s")
          type = GaussianSet::S;
        else if (shellType == "p")
          type = GaussianSet::P;
        else if (shellType == "d" && spherical)
          type = GaussianSet::D5;
        else if (shellType == "d")
          type = GaussianSet::D;
        else if (shellType == "f" && spherical)
          type = GaussianSet::F7;
        else if (shellType == "f")
          type = GaussianSet::F;

        if (type != GaussianSet::UU) {
          int b = basis->addBasis(i, type);
          for (size_t k = 0; k < exponent.size() && k < coefficient.size();
               ++k) {
            basis->addGto(b, coefficient[k], exponent[k]);
          }
        }
      }
    }
    // Now to add the molecular orbital coefficients.
    json moCoeffs = molecularOrbitals.value("molecularOrbital", json());
    vector<double> coeffArray;
    vector<double> energyArray;
    vector<unsigned char> occArray;
    vector<unsigned int> numArray;
    for (size_t i = 0; i < moCoeffs.size(); ++i) {
      json currentMO = moCoeffs[i];
      json coeff = currentMO.value("moCoefficients", json());
      for (size_t j = 0; j < coeff.size(); ++j)
        coeffArray.push_back(coeff[j]);
      if (currentMO.count("orbitalEnergy")) {
        energyArray.push_back(currentMO["orbitalEnergy"].value("value", 0.0));
      }
      if (currentMO.count("orbitalOccupancy")) {
        occArray.push_back(
          static_cast<unsigned char>(currentMO["orbitalOccupancy"]));
      }
      if (currentMO.count("orbitalNumber")) {
        numArray.push_back(
          static_cast<unsigned int>(currentMO["orbitalNumber"]));
      }
    }
    basis->setMolecularOrbitals(coeffArray);
    basis->setMolecularOrbitalEnergy(energyArray);
    basis->setMolecularOrbitalOccupancy(occArray);
    basis->setMolecularOrbitalNumber(numArray);
    basis->setElectronCount(numberOfElectrons);
    basis->setFunctionalName(xcFunctional);
    basis->setName(basisSetName);
    basis->setTheoryName(theory);
    molecule.setBasisSet(basis);
  }

  // Now to see if there was a vibrational frequencies calculation.
  if (!calculationVib.is_null() && calculationVib.is_object()) {
    json normalModes = calculationVib.value("calculationResults", json())
                         .value("normalModes", json());
    if (!normalModes.is_null() && normalModes.is_array()) {
      Array<double> frequencies;
      Array<double> intensities;
      Array<Array<Vector3>> Lx;
      for (size_t i = 0; i < normalModes.size(); ++i) {
        json mode = normalModes[i];
        frequencies.push_back(
          mode.value("normalModeFrequency", json()).value("value", 0.0));
        intensities.push_back(mode.value("normalModeInfraRedIntensity", json())
                                .value("value", 0.0));
        json lx = mode.value("normalModeVector", json()).value("value", json());
        if (!lx.empty() && lx.is_array()) {
          Array<Vector3> modeLx;
          modeLx.resize(lx.size() / 3);
          for (size_t k = 0; k < lx.size(); ++k)
            modeLx[k / 3][k % 3] = lx[k];
          Lx.push_back(modeLx);
        }
      }
      molecule.setVibrationFrequencies(frequencies);
      molecule.setVibrationIntensities(intensities);
      molecule.setVibrationLx(Lx);
    }
  }

  return true;
}

bool NWChemJson::write(std::ostream&, const Molecule&)
{
  return false;
}

vector<std::string> NWChemJson::fileExtensions() const
{
  vector<std::string> ext;
  ext.push_back("json");
  ext.push_back("nwjson");
  return ext;
}

vector<std::string> NWChemJson::mimeTypes() const
{
  vector<std::string> mime;
  mime.push_back("chemical/x-nwjson");
  return mime;
}

} // namespace QuantumIO
} // namespace Avogadro
