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
  Index atomCount = molecule.atomCount();
  if (atomCount == 0) {
    appendError("Error: no atoms found.");
    return false;
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
  if (root.find("connectivity") != root.end() &&
      root["connectivity"].is_array()) {
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
    molecule.setData("name", root["comment"].get<std::string>());

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
        Core::Variant dipoleMoment(dipole[0].get<float>(),
                                   dipole[1].get<float>(),
                                   dipole[2].get<float>());
        molecule.setData("dipoleMoment", dipoleMoment);
      }
    }
    if (properties.find("partial_charges") != properties.end() &&
        properties["partial_charges"].is_object()) {
      // keys are types, values are arrays of charges
      json partialCharges = properties["partial_charges"];
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
    // energy
    // e.g. total_energy": {
    //         "units": "Hartree",
    //        "value": -26.173033542939
    if (properties.find("total_energy") != properties.end() &&
        properties["total_energy"].is_object()) {
      json totalEnergy = properties["total_energy"];
      if (totalEnergy.find("value") != totalEnergy.end())
        molecule.setData("totalEnergy", totalEnergy["value"].get<float>());
    }

    // trajectory or geometry optimization
    if (properties.find("geometry_sequence") != properties.end() &&
        properties["geometry_sequence"].is_object()) {
      json sequence = properties["geometry_sequence"];
      // energies and geometries

      // energies should be a numeric array
      if (sequence.find("energies") != sequence.end() &&
          sequence["energies"].is_array()) {
        std::vector<double> energies;
        for (unsigned int i = 0; i < sequence["energies"].size(); ++i) {
          energies.push_back(sequence["energies"][i].get<float>());
        }
        molecule.setData("energies", energies);
      }

      json coordSets = properties["geometry_sequence"]["geometries"];
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

    // vibrations
    if (properties.find("vibrations") != properties.end() &&
        properties["vibrations"].is_object()) {
      json vib = properties["vibrations"];

      Array<double> freqs, irIntens, ramanIntens;
      Array<Array<Vector3>> disps;

      // frequencies
      if (vib.find("frequencies") != vib.end() &&
          vib["frequencies"].is_array()) {
        json frequencies = vib["frequencies"];
        if (isNumericArray(frequencies)) {
          for (auto& frequency : frequencies) {
            freqs.push_back(static_cast<double>(frequency));
          }
        }
      }
      if (vib.find("intensities") != vib.end() &&
          vib["intensities"].is_object()) {
        json ir = vib["intensities"]["IR"];
        if (isNumericArray(ir)) {
          for (auto& i : ir) {
            irIntens.push_back(static_cast<double>(i));
          }
        }
        json raman = vib["intensities"]["raman"];
        if (isNumericArray(raman)) {
          for (auto& i : raman) {
            ramanIntens.push_back(static_cast<double>(i));
          }
        }
      }

      json displacements = vib["displacement"];
      if (displacements.is_array()) {
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
      }

      // sanity check
      // make sure these all have the same length
      Index size = freqs.size();
      if (size > 0 && irIntens.size() == size && disps.size() == size) {
        molecule.setVibrationFrequencies(freqs);
        molecule.setVibrationIRIntensities(irIntens);
        molecule.setVibrationLx(disps);
      }
      // check to make sure raman intensities are not all zero
      bool allZero = true;
      for (auto& i : ramanIntens) {
        if (i != 0.0) {
          allZero = false;
          break;
        }
      }
      if (ramanIntens.size() == size && !allZero)
        molecule.setVibrationRamanIntensities(ramanIntens);
    }

    // excitation energies
    if (properties.find("excited_states") != properties.end() &&
        properties["excited_states"].is_object()) {
      json excitedStates = properties["excited_states"];
      // check units (defaults to nm)
      std::string units = "nm";
      if (excitedStates.find("units") != excitedStates.end()) {
        units = excitedStates["units"].get<std::string>();
      }
      std::vector<double> energies;
      std::vector<double> intensities;
      // transition_energies
      if (excitedStates.find("transition_energies") != excitedStates.end() &&
          excitedStates["transition_energies"].is_array()) {
        json transition_energies = excitedStates["transition_energies"];
        if (isNumericArray(transition_energies)) {
          for (auto& i : transition_energies) {
            if (units == "nm")
              // convert to eV, i.e. eV = 1239.8 / wavelength
              energies.push_back(1239.841984 / static_cast<double>(i));
            else if (units == "cm^-1")
              energies.push_back(static_cast<double>(i) / 8065.544);
            else if (units == "eV")
              energies.push_back(static_cast<double>(i));
          }
        }
      }
      if (excitedStates.find("intensities") != excitedStates.end() &&
          excitedStates["intensities"].is_array()) {
        json intensities = excitedStates["intensities"];
        if (isNumericArray(intensities)) {
          for (auto& i : intensities) {
            intensities.push_back(static_cast<double>(i));
          }
        }
      }

      // sanity check
      // make sure these all have the same length
      Index size = energies.size();
      if (size > 0 && intensities.size() == size) {
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

    // NMR spectra
    if (properties.find("nmr_shifts") != properties.end() &&
        properties["nmr_shifts"].is_object()) {
      json nmrShifts = properties["nmr_shifts"];
      // get the isotropic shifts as an array
      std::vector<double> nmrShiftsIsotropic;
      if (nmrShifts.find("isotropic") != nmrShifts.end() &&
          nmrShifts["isotropic"].is_array()) {
        json isotropic = nmrShifts["isotropic"];
        if (isNumericArray(isotropic)) {
          for (auto& i : isotropic) {
            nmrShiftsIsotropic.push_back(static_cast<double>(i));
          }
        }
      }

      MatrixX nmrData(nmrShiftsIsotropic.size(), 1);
      for (std::size_t i = 0; i < nmrShiftsIsotropic.size(); ++i) {
        nmrData(i, 0) = nmrShiftsIsotropic[i];
      }
      molecule.setSpectra("NMR", nmrData);
    }

    // todo
    // - orbital energies
    // - other properties
  }

  return true;
}

} // namespace Avogadro::QuantumIO
