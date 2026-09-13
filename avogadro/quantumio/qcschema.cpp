/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "qcschema.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>
#include <avogadro/core/version.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
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

namespace {

/// Thermochemistry, not the electronic energy the molecule wants.
bool isThermochemistry(const std::string& key)
{
  return key == "free_energy" || key == "internal_energy" ||
         key == "zero_point_energy";
}

std::string toLower(std::string text)
{
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return text;
}

/**
 * WebMO writes the electronic energy under a key named for the method it ran
 * -- "uhf_energy", "pm6_energy", "rb3lyp_energy" -- rather than the
 * "total_energy" the specification uses, so every such file would otherwise
 * come in with no energy at all. Prefer the key matching the reported method,
 * and fall back to the first plausible one.
 *
 * Returns a null json when there is nothing to use.
 */
json findMethodEnergy(const json& properties)
{
  std::string method;
  const auto name = properties.find("method_energy_name");
  if (name != properties.end() && name->is_string())
    method = toLower(name->get<std::string>()) + "_energy";

  json fallback;
  for (const auto& item : properties.items()) {
    const std::string& key = item.key();
    if (!Core::endsWith(key, "_energy") || isThermochemistry(key))
      continue;
    if (!item.value().is_object() ||
        item.value().find("value") == item.value().end())
      continue;

    if (!method.empty() && toLower(key) == method)
      return item.value();
    if (fallback.is_null())
      fallback = item.value();
  }
  return fallback;
}

} // namespace

bool QCSchema::read(std::istream& in, Core::Molecule& molecule)
{
  double coordinateScale = 1.0; // default to Angstroms

  // This should be JSON so look for key attributes
  json root;
  try {
    in >> root;
  } catch (const json::exception& e) {
    // Every nlohmann error type, not just parse_error: a number the parser
    // cannot represent throws out_of_range, which would otherwise escape and
    // terminate.
    appendError("Error parsing JSON: " + string(e.what()));
    return false;
  }

  if (!root.is_object()) {
    appendError("Error: Input is not a JSON object.");
    return false;
  }

  // check for 'schema_name'
  const auto schema = root.find("schema_name");
  if (schema == root.end() || !schema->is_string()) {
    appendError("Error: Input is not a QC_JSON object.");
    return false;
  }
  const std::string schemaName = schema->get<std::string>();
  if (schemaName != "QC_JSON" && schemaName != "qcschema_molecule") {
    appendError("Error: Input is not a QC_JSON object.");
    return false;
  }

  // "qcschema_molecule" is the MolSSI specification, while "QC_JSON" is the
  // older WebMO variant. The MolSSI form uses bohr and zero-based connectivity
  // indices, the WebMO one uses Angstroms and one-based indices.
  const bool molssi = schemaName == "qcschema_molecule";
  if (molssi) {
    coordinateScale = BOHR_TO_ANGSTROM;
  }
  const Index indexOffset = molssi ? 0 : 1;

  // get the elements
  if (root.find("symbols") == root.end() || !root["symbols"].is_array()) {
    appendError("Error: no \"symbols\" array found.");
    return false;
  }

  json elements = root["symbols"];
  unsigned char atomicNum(0);
  for (const auto& element : elements) {
    // convert from a string to atomic number
    if (!element.is_string()) {
      appendError("Error: \"symbols\" array must contain element symbols.");
      return false;
    }
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
  if (!isNumericArray(geometry)) {
    appendError("Error: \"geometry\" array must be numeric.");
    return false;
  }
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    auto a = molecule.atom(i);
    Vector3 pos(geometry[3 * i], geometry[3 * i + 1], geometry[3 * i + 2]);
    a.setPosition3d(pos * coordinateScale);
  }

  // check for (optional) connectivity
  if (root.find("connectivity") != root.end() &&
      root["connectivity"].is_array() && !root["connectivity"].empty()) {
    // read the bonds and orders
    json connectivity = root["connectivity"];
    // stored as an array of 3-value arrays start, end, order
    // the order may be fractional in the MolSSI specification
    for (const auto& bond : connectivity) {
      if (!bond.is_array() || bond.size() < 3)
        continue;
      // the endpoints must be integers, the order may be fractional
      if (!bond[0].is_number_integer() || !bond[1].is_number_integer() ||
          !bond[2].is_number())
        continue;
      Index start = bond[0].get<Index>() - indexOffset;
      Index end = bond[1].get<Index>() - indexOffset;
      if (start >= atomCount || end >= atomCount)
        continue;
      // the specification limits bond orders to the range [0, 5]
      double bondOrder = std::min(std::max(bond[2].get<double>(), 0.0), 5.0);
      auto order = static_cast<unsigned char>(std::lround(bondOrder));
      molecule.addBond(start, end, order);
    }
  } else {
    // perceive connectivity
    molecule.perceiveBondsSimple();
    molecule.perceiveBondOrders();
  }

  // check for optional name / comment
  if (root.find("name") != root.end() && root["name"].is_string())
    molecule.setData("name", root["name"].get<std::string>());
  else if (root.find("comment") != root.end() && root["comment"].is_string())
    molecule.setData("name", root["comment"].get<std::string>());

  // check for molecular_charge and molecular_multiplicity
  // (the specification types both of these as floats)
  if (root.find("molecular_charge") != root.end() &&
      root["molecular_charge"].is_number()) {
    molecule.setData("totalCharge", static_cast<int>(std::lround(
                                      root["molecular_charge"].get<double>())));
  }
  if (root.find("molecular_multiplicity") != root.end() &&
      root["molecular_multiplicity"].is_number()) {
    int multiplicity = static_cast<int>(
      std::lround(root["molecular_multiplicity"].get<double>()));
    // some files in the wild write a multiplicity of zero - ignore those and
    // let the molecule work one out from the electron count instead
    if (multiplicity >= 1)
      molecule.setData("totalSpinMultiplicity", multiplicity);
  }

  // if the "properties object exists" look for properties
  if (root.find("properties") != root.end() && root["properties"].is_object()) {
    json properties = root["properties"];

    if (properties.find("dipole_moment") != properties.end()) {
      // read the numeric array
      json dipole = properties["dipole_moment"];
      if (isNumericArray(dipole) && dipole.size() == 3) {
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
    json totalEnergy = properties.value("total_energy", json());
    // The MolSSI specification always uses total_energy, so only the older
    // WebMO dialect gets the method-named fallback, alongside the coordinate
    // and connectivity handling above.
    if (!molssi && !totalEnergy.is_object())
      totalEnergy = findMethodEnergy(properties);
    if (totalEnergy.is_object()) {
      const auto value = totalEnergy.find("value");
      if (value != totalEnergy.end() && value->is_number())
        molecule.setData("totalEnergy", value->get<float>());
    }

    // trajectory or geometry optimization
    if (properties.find("geometry_sequence") != properties.end() &&
        properties["geometry_sequence"].is_object()) {
      json sequence = properties["geometry_sequence"];
      // energies and geometries

      // energies should be a numeric array
      if (sequence.find("energies") != sequence.end() &&
          isNumericArray(sequence["energies"])) {
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
          // every step has to match the atoms we read above
          if (isNumericArray(set) && set.size() == atomCount * 3) {
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
          // each mode is a displacement vector for every atom
          if (isNumericArray(arr) && arr.size() == atomCount * 3) {
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
      if (excitedStates.find("units") != excitedStates.end() &&
          excitedStates["units"].is_string()) {
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
            double value = static_cast<double>(i);
            if (units == "nm") {
              // convert to eV, i.e. eV = 1239.8 / wavelength
              if (value != 0.0)
                energies.push_back(1239.841984 / value);
            } else if (units == "cm^-1")
              energies.push_back(value / 8065.544);
            else if (units == "eV")
              energies.push_back(value);
          }
        }
      }
      if (excitedStates.find("intensities") != excitedStates.end() &&
          excitedStates["intensities"].is_array()) {
        json jsonIntensities = excitedStates["intensities"];
        if (isNumericArray(jsonIntensities)) {
          for (auto& i : jsonIntensities) {
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

      if (!nmrShiftsIsotropic.empty()) {
        MatrixX nmrData(nmrShiftsIsotropic.size(), 1);
        for (std::size_t i = 0; i < nmrShiftsIsotropic.size(); ++i) {
          nmrData(i, 0) = nmrShiftsIsotropic[i];
        }
        molecule.setSpectra("NMR", nmrData);
      }
    }

    // todo
    // - orbital energies
    // - other properties
  }

  return true;
}

namespace {

/**
 * QCSchema requires the provenance version to be a PEP 440 string, but our
 * version may carry a git description (e.g. "2.0.0-209-gcae74147"). Keep the
 * leading numeric release and move anything that follows into a local version
 * label, e.g. "2.0.0+209.gcae74147".
 */
std::string pep440Version(const std::string& version)
{
  std::string::size_type end = version.find_first_not_of("0123456789.");
  std::string release = version.substr(0, end);
  // trim any trailing separator left behind, e.g. "2.0.0-" => "2.0.0"
  while (!release.empty() && release.back() == '.')
    release.pop_back();
  if (release.empty())
    return "0";
  if (end == std::string::npos)
    return release;

  // the local label allows only lowercase alphanumerics separated by periods
  std::string local;
  for (std::string::size_type i = end; i < version.size(); ++i) {
    char c = version[i];
    if (std::isalnum(static_cast<unsigned char>(c)))
      local += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    else if (!local.empty() && local.back() != '.')
      local += '.';
  }
  while (!local.empty() && local.back() == '.')
    local.pop_back();
  if (local.empty())
    return release;

  return release + "+" + local;
}

} // namespace

bool QCSchema::write(std::ostream& out, const Core::Molecule& molecule)
{
  const Index atomCount = molecule.atomCount();
  if (atomCount == 0) {
    appendError("Error: no atoms to write.");
    return false;
  }
  // custom / dummy elements have no elemental symbol, so they cannot be
  // expressed in a qcschema_molecule
  if (molecule.hasCustomElements()) {
    appendError("Error: QCSchema cannot represent custom elements.");
    return false;
  }

  // use an ordered object so the output is stable and human readable
  ordered_json root;

  root["schema_name"] = "qcschema_molecule";
  root["schema_version"] = 3;

  if (molecule.data("name").type() == Core::Variant::String) {
    std::string name = molecule.data("name").toString();
    if (!name.empty())
      root["name"] = name;
  }
  if (molecule.data("comment").type() == Core::Variant::String) {
    std::string comment = molecule.data("comment").toString();
    if (!comment.empty())
      root["comment"] = comment;
  }

  // the ordered array of elemental symbols, in title case
  ordered_json symbols = ordered_json::array();
  const auto& atomicNumbers = molecule.atomicNumbers();
  for (Index i = 0; i < atomCount; ++i)
    symbols.push_back(Elements::symbol(atomicNumbers[i]));
  root["symbols"] = symbols;

  // geometry is a flat (3 * nat) array in bohr
  ordered_json geometry = ordered_json::array();
  const auto& positions = molecule.atomPositions3d();
  for (Index i = 0; i < atomCount; ++i) {
    const Vector3& pos = positions[i];
    for (unsigned int j = 0; j < 3; ++j)
      geometry.push_back(pos[j] * ANGSTROM_TO_BOHR);
  }
  root["geometry"] = geometry;

  // both of these are typed as floats by the specification, and the
  // multiplicity must be positive
  root["molecular_charge"] = static_cast<double>(molecule.totalCharge());
  root["molecular_multiplicity"] =
    static_cast<double>(std::max<int>(molecule.totalSpinMultiplicity(), 1));

  // connectivity is optional, and must be omitted rather than left empty
  // each entry is (index a, index b, bond order) with zero-based indices
  if (molecule.bondCount() > 0) {
    ordered_json connectivity = ordered_json::array();
    const auto& bondPairs = molecule.bondPairs();
    const auto& bondOrders = molecule.bondOrders();
    for (Index i = 0; i < molecule.bondCount(); ++i) {
      // the specification limits bond orders to the range [0, 5]
      double order = std::min(static_cast<double>(bondOrders[i]), 5.0);
      connectivity.push_back(ordered_json::array(
        { bondPairs[i].first, bondPairs[i].second, order }));
    }
    root["connectivity"] = connectivity;
  }

  // the coordinates come from the user, so ask that they be left alone rather
  // than re-centered and re-oriented by the consumer
  root["fix_com"] = true;
  root["fix_orientation"] = true;

  root["provenance"] = { { "creator", "Avogadro" },
                         { "version", pep440Version(Avogadro::version()) },
                         { "routine", "Avogadro::QuantumIO::QCSchema" } };

  out << std::setw(2) << root << '\n';

  return out.good();
}

} // namespace Avogadro::QuantumIO
