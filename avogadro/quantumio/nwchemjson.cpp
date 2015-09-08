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

#include <jsoncpp.cpp>

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

NWChemJson::NWChemJson()
{
}

NWChemJson::~NWChemJson()
{
}

bool NWChemJson::read(std::istream &file, Molecule &molecule)
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
  Value calculationVib;
  for (size_t i = 0; i < calculations.size(); ++i) {
    Value calcObj = calculations.get(i, "");
    if (calcObj.isObject()) {
      string calcType = calcObj["calculationType"].asString();
      // Store the last vibrational frequencies calculation object.
      if (calcType == "vibrationalFrequencies")
        calculationVib = calcObj;
      Value calcSetup = calcObj["calculationSetup"];
      Value calcMol = calcSetup["molecule"];
      string calcMolStr = calcMol.toStyledString();
      if (!calcMol.isNull() && calcMol.isObject()) {
        calcMolStr = "Object with id: " + calcMol["id"].asString();
        moleculeArray.append(calcMol);
      }

      Value calcResults = calcObj["calculationResults"];
      calcMol = calcResults["molecule"];
      if (!calcMol.isNull() && calcMol.isObject()) {
        calcMolStr = "Object with id: " + calcMol["id"].asString();
        moleculeArray.append(calcMol);
      }
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
      Atom a =
          molecule.addAtom(static_cast<unsigned char>(jsonAtom["elementNumber"]
                           .asInt()));
      Value pos = jsonAtom["cartesianCoordinates"]["value"];
      a.setPosition3d(Vector3(pos.get(Json::Value::ArrayIndex(0), 0.0).asDouble() * BOHR_TO_ANGSTROM_D,
                              pos.get(Json::Value::ArrayIndex(1), 0.0).asDouble() * BOHR_TO_ANGSTROM_D,
                              pos.get(Json::Value::ArrayIndex(2), 0.0).asDouble() * BOHR_TO_ANGSTROM_D));
    }
  }
  // Perceive bonds for the molecule.
  molecule.perceiveBondsSimple();

  // Now to see if there was a vibrational frequencies calculation.
  if (!calculationVib.isNull() && calculationVib.isObject()) {
    Value normalModes = calculationVib["calculationResults"]["normalModes"];
    if (!normalModes.isNull() && normalModes.isArray()) {
      Array<double> frequencies;
      Array<double> intensities;
      Array< Array<Vector3> > Lx;
      for (size_t i = 0; i < normalModes.size(); ++i) {
        Value mode = normalModes.get(i, "");
        frequencies.push_back(mode["normalModeFrequency"]["value"].asDouble());
        intensities.push_back(mode["normalModeInfraRedIntensity"]["value"].asDouble());
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

bool NWChemJson::write(std::ostream &file, const Molecule &molecule)
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
