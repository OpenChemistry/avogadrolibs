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

#include <json/json.h>

#include <iostream>

namespace Avogadro {
namespace QuantumIO {

using std::string;
using std::vector;
using std::cout;
using std::endl;

using Json::Value;
using Json::Reader;
using Json::StyledStreamWriter;

using Core::Array;
using Core::Atom;
using Core::BasisSet;
using Core::Bond;
using Core::CrystalTools;
using Core::Elements;
using Core::GaussianSet;
using Core::Molecule;
using Core::Variant;
using Core::split;

NWChemJson::NWChemJson()
{
}

NWChemJson::~NWChemJson()
{
}

bool NWChemJson::read(std::istream& file, Molecule& molecule)
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

  Value simulation = root["simulation"];
  if (simulation.empty()) {
    appendError("Error: no \"simulation\" key found.");
    return false;
  }

  // Scan the calculations array for calculationSetup.molecule objects.
  Value calculations = simulation["calculations"];
  if (calculations.empty() || !calculations.isArray()) {
    appendError("Error: no \"calculations\" array found.");
    return false;
  }

  // Iterate through the objects in the array, and print out any molecules.
  Value moleculeArray(Json::arrayValue);
  Value basisSetArray(Json::arrayValue);
  Value calculationVib;
  Value molecularOrbitals;
  int numberOfElectrons = 0;
  for (size_t i = 0; i < calculations.size(); ++i) {
    Value calcObj = calculations.get(i, "");
    if (calcObj.isObject()) {
      string calcType = calcObj["calculationType"].asString();
      // Store the last vibrational frequencies calculation object.
      if (calcType == "vibrationalModes")
        calculationVib = calcObj;
      Value calcSetup = calcObj["calculationSetup"];
      Value calcMol = calcSetup["molecule"];
      numberOfElectrons = calcSetup["numberOfElectrons"].asInt();
      if (!calcMol.isNull() && calcMol.isObject())
        moleculeArray.append(calcMol);
      Value basisSet = calcSetup["basisSet"];
      if (!basisSet.isNull() && basisSet.isObject())
        basisSetArray.append(basisSet);

      Value calcResults = calcObj["calculationResults"];
      calcMol = calcResults["molecule"];
      if (!calcMol.isNull() && calcMol.isObject())
        moleculeArray.append(calcMol);
      // There is currently one id for all, just get the last one we find.
      if (!calcResults["molecularOrbitals"].isNull() &&
          calcResults["molecularOrbitals"].isObject())
        molecularOrbitals = calcResults["molecularOrbitals"];
    }
  }

  // For now, we are just grabbing the "last" molecule, and using that. This
  // needs more complex logic to step through the file and do it properly.
  Value finalMol = moleculeArray.get(moleculeArray.size() - 1, 0);
  Value atoms = finalMol["atoms"];
  if (atoms.isArray()) {
    for (size_t i = 0; i < atoms.size(); ++i) {
      Value jsonAtom = atoms.get(i, 0);
      if (jsonAtom.isNull() || !jsonAtom.isObject())
        continue;
      Atom a = molecule.addAtom(
        static_cast<unsigned char>(jsonAtom["elementNumber"].asInt()));
      Value pos = jsonAtom["cartesianCoordinates"]["value"];
      Vector3 position(pos.get(Json::Value::ArrayIndex(0), 0.0).asDouble(),
                       pos.get(Json::Value::ArrayIndex(1), 0.0).asDouble(),
                       pos.get(Json::Value::ArrayIndex(2), 0.0).asDouble());
      string units = jsonAtom["cartesianCoordinates"]["units"].asString();
      if (units == "bohr")
        position *= BOHR_TO_ANGSTROM_D;
      a.setPosition3d(position);
    }
  }
  // Perceive bonds for the molecule.
  molecule.perceiveBondsSimple();

  // Add in the electronic structure information if available.
  if (molecularOrbitals.isObject() &&
      molecularOrbitals["atomicOrbitalDescriptions"].isArray()) {
    Value basisSet = basisSetArray.get(basisSetArray.size() - 1, 0);
    Value orbDesc = molecularOrbitals["atomicOrbitalDescriptions"];

    // Figure out the mapping of basis set to molecular orbitals.
    Array<int> atomNumber;
    Array<string> atomSymbol;
    for (size_t i = 0; i < orbDesc.size(); ++i) {
      string desc = orbDesc.get(i, 0).asString();
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
    for (size_t i = 0; i < atomSymbol.size(); ++i) {
      string symbol = atomSymbol[i];
      Value basisFunctions = basisSet["basisFunctions"];
      Value currentFunction;
      for (size_t j = 0; j < basisFunctions.size(); ++j) {
        currentFunction = basisFunctions.get(j, 0);

        string elementType;
        if (currentFunction.isMember("elementLabel"))
          elementType = currentFunction["elementLabel"].asString();
        else if (currentFunction.isMember("elementType"))
          elementType = currentFunction["elementType"].asString();

        if (elementType == symbol)
          break;

        currentFunction = Json::nullValue;
      }

      if (currentFunction.isNull())
        break;

      Value contraction = currentFunction["basisSetContraction"];
      bool spherical =
        currentFunction["basisSetHarmonicType"].asString() == "spherical";
      for (size_t j = 0; j < contraction.size(); ++j) {
        Value contractionShell = contraction.get(j, Json::nullValue);
        string shellType;
        if (contractionShell.isMember("basisSetShell"))
          shellType = contractionShell["basisSetShell"].asString();
        else if (contractionShell.isMember("basisSetShellType"))
          shellType = contractionShell["basisSetShellType"].asString();
        Value exponent = contractionShell["basisSetExponent"];
        Value coefficient = contractionShell["basisSetCoefficient"];
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
          type == GaussianSet::F;

        if (type != GaussianSet::UU) {
          int b = basis->addBasis(i, type);
          for (size_t k = 0; k < exponent.size(); ++k) {
            basis->addGto(b, coefficient.get(k, 0).asDouble(),
                          exponent.get(k, 0).asDouble());
          }
        }
      }
    }
    // Now to add the molecular orbital coefficients.
    Value moCoeffs = molecularOrbitals["molecularOrbital"];
    vector<double> coeffArray;
    vector<double> energyArray;
    vector<unsigned char> occArray;
    vector<unsigned int> numArray;
    for (size_t i = 0; i < moCoeffs.size(); ++i) {
      Value currentMO = moCoeffs.get(i, Json::nullValue);
      Value coeff = currentMO["moCoefficients"];
      for (size_t j = 0; j < coeff.size(); ++j)
        coeffArray.push_back(coeff.get(j, 0).asDouble());
      if (currentMO.isMember("orbitalEnergy"))
        energyArray.push_back(currentMO["orbitalEnergy"]["value"].asDouble());
      if (currentMO.isMember("orbitalOccupancy"))
        occArray.push_back(
          static_cast<unsigned char>(currentMO["orbitalOccupancy"].asInt()));
      if (currentMO.isMember("orbitalNumber"))
        numArray.push_back(
          static_cast<unsigned int>(currentMO["orbitalNumber"].asInt()));
    }
    basis->setMolecularOrbitals(coeffArray);
    basis->setMolecularOrbitalEnergy(energyArray);
    basis->setMolecularOrbitalOccupancy(occArray);
    basis->setMolecularOrbitalNumber(numArray);
    basis->setElectronCount(numberOfElectrons);
    molecule.setBasisSet(basis);
  }

  // Now to see if there was a vibrational frequencies calculation.
  if (!calculationVib.isNull() && calculationVib.isObject()) {
    Value normalModes = calculationVib["calculationResults"]["normalModes"];
    if (!normalModes.isNull() && normalModes.isArray()) {
      Array<double> frequencies;
      Array<double> intensities;
      Array<Array<Vector3>> Lx;
      for (size_t i = 0; i < normalModes.size(); ++i) {
        Value mode = normalModes.get(i, "");
        frequencies.push_back(mode["normalModeFrequency"]["value"].asDouble());
        intensities.push_back(
          mode["normalModeInfraRedIntensity"]["value"].asDouble());
        Value lx = mode["normalModeVector"]["value"];
        if (!lx.empty() && lx.isArray()) {
          Array<Vector3> modeLx;
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
  }

  return true;
}

bool NWChemJson::write(std::ostream& file, const Molecule& molecule)
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

} // end QuantumIO namespace
} // end Avogadro namespace
