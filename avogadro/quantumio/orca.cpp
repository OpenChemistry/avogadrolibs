/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orca.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <regex>

using std::regex;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Array;
using Core::Atom;
using Core::GaussianSet;

ORCAOutput::ORCAOutput() {}

ORCAOutput::~ORCAOutput() {}

constexpr double BOHR_TO_ANGSTROM = 0.529177210544;
constexpr double HARTREE_TO_EV = 27.211386245981;

std::vector<std::string> ORCAOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("orca");
  return extensions;
}

std::vector<std::string> ORCAOutput::mimeTypes() const
{
  return std::vector<std::string>();
}

bool ORCAOutput::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line
  auto* basis = new GaussianSet;

  while (!in.eof())
    processLine(in, basis);

  // Set up the molecule
  int nAtom = 0;
  for (unsigned int i = 0; i < m_atomNums.size(); i++) {
    Vector3 pos = m_atomPos[i] * BOHR_TO_ANGSTROM;
    molecule.addAtom(static_cast<unsigned char>(m_atomNums[nAtom++]), pos);
  }

  if (0 == molecule.atomCount()) {
    appendError("Could not find any atomic coordinates! Are you sure this is "
                "an ORCA output file?");
    return false;
  }

  // this should be the final coordinate set (e.g. the optimized geometry)
  molecule.setCoordinate3d(molecule.atomPositions3d(), 0);
  if (m_coordSets.size() > 1) {
    for (unsigned int i = 0; i < m_coordSets.size(); i++) {
      Array<Vector3> positions;
      positions.reserve(molecule.atomCount());
      for (size_t j = 0; j < molecule.atomCount(); ++j) {
        positions.push_back(m_coordSets[i][j] * BOHR_TO_ANGSTROM);
      }
      molecule.setCoordinate3d(positions, i + 1);
    }
  }

  // guess bonds and bond orders
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();

  if (m_frequencies.size() > 0 &&
      m_frequencies.size() == m_vibDisplacements.size() &&
      m_frequencies.size() == m_IRintensities.size()) {
    molecule.setVibrationFrequencies(m_frequencies);
    molecule.setVibrationIRIntensities(m_IRintensities);
    molecule.setVibrationLx(m_vibDisplacements);
    if (m_RamanIntensities.size())
      molecule.setVibrationRamanIntensities(m_RamanIntensities);
  }

  if (m_electronicTransitions.size() > 0 &&
      m_electronicTransitions.size() == m_electronicIntensities.size()) {
    MatrixX electronicData(m_electronicTransitions.size(), 2);
    for (size_t i = 0; i < m_electronicTransitions.size(); ++i) {
      electronicData(i, 0) = m_electronicTransitions[i];
      electronicData(i, 1) = m_electronicIntensities[i];
    }
    molecule.setSpectra("Electronic", electronicData);

    if (m_electronicRotations.size() == m_electronicTransitions.size()) {
      MatrixX electronicRotations(m_electronicTransitions.size(), 2);
      for (size_t i = 0; i < m_electronicTransitions.size(); ++i) {
        electronicRotations(i, 0) = m_electronicTransitions[i];
        electronicRotations(i, 1) = m_electronicRotations[i];
      }
      molecule.setSpectra("CircularDichroism", electronicRotations);
    }
  }

  if (m_nmrShifts.size() > 0) {
    MatrixX nmrData(m_nmrShifts.size(), 2);
    // nmr_shifts has an entry for every atom even if not computed
    for (size_t i = 0; i < m_nmrShifts.size(); ++i) {
      nmrData(i, 0) = m_nmrShifts[i];
      nmrData(i, 1) = 1.0;
    }
    molecule.setSpectra("NMR", nmrData);
  }

  // check bonds from calculated bond orders
  if (m_bondOrders.size() > 0) {
    for (unsigned int i = 0; i < m_bondOrders.size(); i++) {
      // m_bondOrders[i][0] is the first atom
      // m_bondOrders[i][1] is the second atom
      // m_bondOrders[i][2] is the bond order
      if (m_bondOrders[i].size() > 2) {
        auto bond = molecule.bond(m_bondOrders[i][0], m_bondOrders[i][1]);
        if (bond.isValid() && bond.order() != m_bondOrders[i][2]) {
          // if the bond order is different, change it
          bond.setOrder(static_cast<unsigned char>(m_bondOrders[i][2]));
        }
      }
    }
  }

  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);

  // we have to do a few things *after* any modifications to bonds / atoms
  // because those automatically clear partial charges and data

  // add the partial charges
  if (m_partialCharges.size() > 0) {
    for (auto it = m_partialCharges.begin(); it != m_partialCharges.end();
         ++it) {
      molecule.setPartialCharges(it->first, it->second);
    }
  }

  molecule.setData("totalCharge", m_charge);
  molecule.setData("totalSpinMultiplicity", m_spin);
  molecule.setData("dipoleMoment", m_dipoleMoment);
  molecule.setData("totalEnergy", m_totalEnergy);
  if (m_energies.size() > 1)
    molecule.setData("energies", m_energies);

  return true;
}

void ORCAOutput::processLine(std::istream& in,
                             [[maybe_unused]] GaussianSet* basis)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  string key = Core::trimmed(line);
  vector<string> list;
  int nGTOs = 0;
  [[maybe_unused]] float vibScaling = 1.0f;

  if (Core::contains(key, "CARTESIAN COORDINATES (A.U.)")) {
    m_coordFactor = 1.; // leave the coords in BOHR ....
    m_currentMode = Atoms;
    // if there are any current coordinates, push them back
    if (m_atomPos.size() > 0) {
      m_coordSets.push_back(m_atomPos);
    }
    m_atomPos.clear();
    m_atomNums.clear();
    m_atomLabel.clear();
    getline(in, key); // skip ----- line
    getline(in, key); // column titles
  } else if (Core::contains(key, "BASIS SET INFORMATION")) {
    if (!Core::contains(key, "AUXILIARY")) { // skip auxiliary basis set infos
      m_currentMode = GTO;
      getline(in, key); // skip ----- line

      // Number of groups of distinct atoms
      getline(in, key);
      list = Core::split(key, ' ');
      if (list.size() > 3) {
        m_nGroups = Core::lexicalCast<int>(list[2]).value_or(0);
      } else {
        return;
      }
      getline(in, key); // skip blank line
      for (int i = 0; i < m_nGroups; ++i) {
        getline(in, key); // skip group information
      }
      getline(in, key); // skip blank line
      for (unsigned int i = 0; i < m_atomNums.size(); ++i) {
        getline(in, key); // skip group information
      }

      // now skip
      // blank line
      // ----------------------------
      // # Basis set for element : x
      // ----------------------------
      // blank line
      for (unsigned int i = 0; i < 6; ++i) {
        getline(in, key);
      }
    }
  } else if (Core::contains(key, "Total Charge")) {
    list = Core::split(key, ' ');
    if (list.size() > 4)
      m_charge = Core::lexicalCast<int>(list[4]).value_or(0);
  } else if (Core::contains(key, "Multiplicity")) {
    list = Core::split(key, ' ');
    if (list.size() > 3)
      m_spin = Core::lexicalCast<int>(list[3]).value_or(1);
  } else if (Core::contains(key, "FINAL SINGLE POINT ENERGY")) {
    list = Core::split(key, ' ');
    if (list.size() > 4)
      m_totalEnergy = Core::lexicalCast<double>(list[4]).value_or(0.0);
    m_energies.push_back(m_totalEnergy);
  } else if (Core::contains(key, "TOTAL NUMBER OF BASIS SET")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (Core::contains(key, "NUMBER OF CARTESIAN GAUSSIAN BASIS")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (Core::contains(key, "Number of Electrons")) {
    list = Core::split(key, ' ');
    m_electrons = Core::lexicalCast<int>(list[5]).value_or(0);
  } else if (Core::contains(key, "Total Dipole Moment")) {
    list = Core::split(key, ' ');
    m_dipoleMoment =
      Eigen::Vector3d(Core::lexicalCast<double>(list[4]).value_or(0.0),
                      Core::lexicalCast<double>(list[5]).value_or(0.0),
                      Core::lexicalCast<double>(list[6]).value_or(0.0));
    // convert from atomic units to Debye
    // e.g. https://en.wikipedia.org/wiki/Debye
    m_dipoleMoment *= 2.54174628;
  } else if (Core::contains(key, "Mayer bond orders")) {
    m_currentMode = BondOrders;
    // starts at the next line
  } else if (Core::contains(
               key,
               "ABSORPTION SPECTRUM VIA TRANSITION ELECTRIC DIPOLE MOMENTS")) {
    m_currentMode = Electronic;
    for (int i = 0; i < 4; ++i) {
      getline(in, key); // skip header
    }
    // starts at the next line
  } else if (Core::contains(key, "CD SPECTRUM") &&
             !Core::contains(key, "TRANSITION VELOCITY DIPOLE")) {
    m_currentMode = ECD;
    for (int i = 0; i < 4; ++i) {
      getline(in, key); // skip header
    }
  } else if (Core::contains(key, "ORBITAL ENERGIES")) {
    m_currentMode = OrbitalEnergies;
    getline(in, key); // skip ------------
    getline(in, key); // check if SPIN UP ORBITALS are present
    if (Core::contains(key, "SPIN UP ORBITALS")) {
      m_openShell = true;
      m_readBeta = false;
    } else {
      m_openShell = false;
      m_readBeta = false;
    }
    getline(in, key); // skip column titles
  } else if (Core::contains(key, "SPIN DOWN ORBITALS")) {
    m_currentMode = OrbitalEnergies;
    m_openShell = true;
    m_readBeta = true;
    getline(in, key); // skip column headers
  } else if (Core::contains(key, "MOLECULAR ORBITALS")) {
    m_currentMode = MO;
    getline(in, key); //------------
  } else if (Core::contains(key, "HIRSHFELD ANALYSIS")) {
    m_currentMode = HirshfeldCharges;
    m_chargeType = "Hirshfeld";
    for (unsigned int i = 0; i < 6; ++i) {
      getline(in, key); // skip header
    }
  } else if (Core::contains(key, "MBIS ANALYSIS")) {
    // MBIS analysis is similar to Hirshfeld, but with different headers
    m_currentMode = HirshfeldCharges;
    m_chargeType = "MBIS";
    for (unsigned int i = 0; i < 9; ++i) {
      getline(in, key); // skip header
    }
  } else if (Core::contains(key, "CHELPG Charges")) {
    // similar to standard charges
    m_currentMode = Charges;
    m_chargeType = "CHELPG";
    getline(in, key); // skip ------------
  } else if (Core::contains(key, "RESP Charges")) {
    m_currentMode = Charges;
    m_chargeType = "RESP";
    getline(in, key); // skip ------------
  } else if (Core::contains(key, "ATOMIC CHARGES")) {
    m_currentMode = Charges;
    // figure out what type of charges we have
    list = Core::split(key, ' ');
    if (list.size() > 2) {
      m_chargeType = Core::trimmed(list[0]); // e.g. MULLIKEN or LOEWDIN
    }
    // lowercase everything except the first letter
    for (unsigned int i = 1; i < m_chargeType.size(); ++i) {
      m_chargeType[i] = tolower(m_chargeType[i]);
    }
    getline(in, key); // skip ------------
  } else if (Core::contains(key, "VIBRATIONAL FREQUENCIES")) {
    m_currentMode = Frequencies;
    getline(in, key); // skip ------------
    getline(in, key); // skip blank line
    getline(in, key); // scaling factor
    // Scaling factor for frequencies =  1.000000000
    list = Core::split(key, ' ');
    if (list.size() > 6)
      vibScaling = Core::lexicalCast<float>(list[5]).value_or(0);
    getline(in, key); // skip blank line
  } else if (Core::contains(key, "NORMAL MODES")) {
    m_currentMode = VibrationalModes;

    getline(in, key); // skip ------------
    getline(in, key); // skip blank line
    getline(in, key); // skip comment
    getline(in, key); // skip more comments
    getline(in, key); // skip even more comment
    getline(in, key); // skip blank line
  } else if (Core::contains(key, "IR SPECTRUM")) {
    m_currentMode = IR;
    getline(in, key); // skip ------------
    getline(in, key); // skip blank line
    getline(in, key); // skip column titles
    getline(in, key); // skip more column titles
    getline(in, key); // skip ------------
  } else if (Core::contains(key, "RAMAN SPECTRUM")) {
    m_currentMode = Raman;
    getline(in, key); // skip ------------
    getline(in, key); // skip blank line
    getline(in, key); // skip column titles
    getline(in, key); // skip ------------
  } else if (Core::contains(key, "CHEMICAL SHIELDING SUMMARY (ppm)")) {
    m_currentMode = NMR;
    for (int i = 0; i < 4; ++i) {
      getline(in, key); // skip header
    }
  } else {

    vector<vector<double>> columns;
    unsigned int numColumns, numRows;
    numColumns = 0;
    numRows = 0;
    // parsing a line -- what mode are we in?

    switch (m_currentMode) {
      case Atoms: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        while (!key.empty()) {
          if (list.size() < 8) {
            break;
          }
          Eigen::Vector3d pos(
            Core::lexicalCast<double>(list[5]).value_or(0.0) * m_coordFactor,
            Core::lexicalCast<double>(list[6]).value_or(0.0) * m_coordFactor,
            Core::lexicalCast<double>(list[7]).value_or(0.0) * m_coordFactor);

          unsigned char atomicNum =
            Core::Elements::atomicNumberFromSymbol(Core::trimmed(list[1]));
          m_atomNums.push_back(atomicNum);
          m_atomPos.push_back(pos);
          m_atomLabel.push_back(Core::trimmed(list[1]));
          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }
        m_currentMode = NotParsing;
        break;
      }
      case HirshfeldCharges: {
        // should start at the first atom
        if (key.empty())
          break;

        Eigen::MatrixXd charges(m_atomNums.size(), 1);
        charges.setZero();

        list = Core::split(key, ' ');
        while (!key.empty()) {
          if (list.size() < 4) {
            break;
          }
          // e.g. index atom charge spin
          // e.g. 0 O   -0.714286   0.000
          int atomIndex = Core::lexicalCast<int>(list[0]).value_or(0);
          double charge = Core::lexicalCast<double>(list[2]).value_or(0.0);
          charges(atomIndex, 0) = charge;

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }

        m_partialCharges[m_chargeType] = charges;
        m_currentMode = NotParsing;
        break;
      }
      case Charges: {
        // should start at the first atom
        if (key.empty())
          break;

        Eigen::MatrixXd charges(m_atomNums.size(), 1);
        charges.setZero();

        list = Core::split(key, ' ');
        while (!key.empty()) {
          if (list.size() != 4) {
            break;
          }
          // e.g. 0 O :   -0.714286
          int atomIndex = Core::lexicalCast<int>(list[0]).value_or(0);
          double charge = Core::lexicalCast<double>(list[3]).value_or(0.0);
          charges(atomIndex, 0) = charge;

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }
        m_partialCharges[m_chargeType] = charges;
        m_currentMode = NotParsing;
        break;
      }
      case BondOrders: {
        if (key.empty())
          break;

        m_bondOrders.clear();
        while (key[0] == 'B') {
          // @todo .. parse the bonds based on character position
          // e.g. B(  0-Ru,  1-C ) :   0.4881 B(  0-Ru,  4-C ) :   0.6050
          Index firstAtom =
            Core::lexicalCast<Index>(key.substr(2, 3)).value_or(0);
          Index secondAtom =
            Core::lexicalCast<Index>(key.substr(9, 3)).value_or(0);
          double bondOrder =
            Core::lexicalCast<double>(key.substr(18, 9)).value_or(0.0);

          if (bondOrder > 1.6) {
            std::vector<int> bond;
            bond.push_back(static_cast<int>(firstAtom));
            bond.push_back(static_cast<int>(secondAtom));
            bond.push_back(static_cast<int>(std::round(bondOrder)));
            m_bondOrders.push_back(bond);
          }

          if (key.size() > 54 && key[28] == 'B') {
            firstAtom = Core::lexicalCast<Index>(key.substr(30, 3)).value_or(0);
            secondAtom =
              Core::lexicalCast<Index>(key.substr(37, 3)).value_or(0);
            bondOrder =
              Core::lexicalCast<double>(key.substr(46, 9)).value_or(0.0);

            if (bondOrder > 1.6) {
              std::vector<int> bond;
              bond.push_back(static_cast<int>(firstAtom));
              bond.push_back(static_cast<int>(secondAtom));
              bond.push_back(static_cast<int>(std::round(bondOrder)));
              m_bondOrders.push_back(bond);
            }
          }
          if (key.size() > 82 && key[56] == 'B') {
            firstAtom = Core::lexicalCast<Index>(key.substr(58, 3)).value_or(0);
            secondAtom =
              Core::lexicalCast<Index>(key.substr(65, 3)).value_or(0);
            bondOrder =
              Core::lexicalCast<double>(key.substr(74, 9)).value_or(0.0);

            if (bondOrder > 1.6) {
              std::vector<int> bond;
              bond.push_back(static_cast<int>(firstAtom));
              bond.push_back(static_cast<int>(secondAtom));
              bond.push_back(static_cast<int>(std::round(bondOrder)));
              m_bondOrders.push_back(bond);
            }
          }

          getline(in, key);
          key = Core::trimmed(key);
        }

        m_currentMode = NotParsing;
        break;
      }
      case OrbitalEnergies: {
        if (key.empty())
          break;

        // should start at the first orbital
        if (!m_readBeta)
          m_orbitalEnergy.clear();
        else
          m_betaOrbitalEnergy.clear();

        list = Core::split(key, ' ');
        while (!key.empty()) {
          if (list.size() != 4) {
            break;
          }

          // energy in Hartree in 3rd column in eV in 4th column
          double energy = Core::lexicalCast<double>(list[3]).value_or(0.0);
          if (!m_readBeta)
            m_orbitalEnergy.push_back(energy);
          else
            m_betaOrbitalEnergy.push_back(energy);

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }
        m_currentMode = NotParsing;
        break;
      }
      case Frequencies: {
        // should start at the first frequency - include zeros
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        while (!key.empty()) {
          // imaginary frequencies can have an additional comment:
          // ***imaginary mode***
          if (list.size() != 3 &&
              (list.size() != 5 || list[3] != "***imaginary" ||
               list[4] != "mode***")) {
            break;
          }
          // e.g. 0:         0.00 cm**-1
          double freq = Core::lexicalCast<double>(list[1]).value_or(0.0);
          m_frequencies.push_back(freq);

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }

        // okay, now set up the normal mode arrays
        m_vibDisplacements.resize(m_frequencies.size());
        m_IRintensities.resize(m_frequencies.size());
        // we don't bother with Raman, because that's less common
        for (unsigned int i = 0; i < m_frequencies.size(); i++) {
          m_IRintensities[i] = 0.0;
          m_vibDisplacements[i].resize(m_atomNums.size());
          for (unsigned int j = 0; j < m_atomNums.size(); j++)
            m_vibDisplacements[i].push_back(Eigen::Vector3d());
        }

        m_currentMode = NotParsing;
        break;
      }
      case VibrationalModes: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        vector<std::size_t> modeIndex;
        bool invalid_index = false;
        while (!key.empty()) {
          // first we get a set of column numbers
          // e.g. 1  2  3  4  5  6  7  8  9 10
          modeIndex.clear();
          for (const auto& index_str : list) {
            auto index = Core::lexicalCast<std::size_t>(index_str).value_or(0);
            if (index >= m_frequencies.size()) {
              invalid_index = true;
              break;
            }
            modeIndex.push_back(index);
          }
          // invalid column index
          if (invalid_index)
            break;

          // now we read the displacements .. there should be 3N lines
          // x,y,z for each atom
          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
          for (unsigned int i = 0; i < 3 * m_atomNums.size(); i++) {
            unsigned int atomIndex = i / 3;
            unsigned int coordIndex = i % 3;
            for (unsigned int j = 0; j < modeIndex.size(); j++) {
              m_vibDisplacements[modeIndex[j]][atomIndex][coordIndex] =
                Core::lexicalCast<double>(list[j + 1]).value_or(0.0);
            }

            getline(in, key);
            key = Core::trimmed(key);
            list = Core::split(key, ' ');
          }
        }

        m_currentMode = NotParsing;
        break;
      }
      case IR: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        while (!key.empty()) {
          // e.g. 6:   1711.76   0.014736   74.47  0.002686  (-0.021704 0.027180
          // 0.038427)
          if (list.size() < 7) {
            break;
          }
          // the first entry might be 5 or 6 because of removed rotations /
          // translations
          auto index = Core::lexicalCast<std::size_t>(list[0]).value_or(0);
          // invalid index
          if (index >= m_frequencies.size())
            break;

          double intensity = Core::lexicalCast<double>(list[3]).value_or(0.0);
          m_IRintensities[index] = intensity;

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }

        m_currentMode = NotParsing;
        break;
      }
      case Raman: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        while (!key.empty()) {
          // e.g.    6:        76.62      0.000000      0.465517
          if (list.size() != 4) {
            break;
          }
          // the first entry might be 5 or 6 because of removed rotations /
          // translations
          auto index = Core::lexicalCast<std::size_t>(list[0]).value_or(0);
          // invalid index
          if (index >= m_frequencies.size())
            break;
          if (m_RamanIntensities.empty()) {
            while (m_RamanIntensities.size() < index) {
              m_RamanIntensities.push_back(0.0);
            }
          }
          // index, frequency, activity, depolarization
          double activity = Core::lexicalCast<double>(list[2]).value_or(0.0);
          m_RamanIntensities.push_back(activity);

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }

        m_currentMode = NotParsing;
        break;
      }
      case Electronic: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        double wavenumbers;
        while (!key.empty()) {
          // should have 8 columns
          if (list.size() < 8) {
            getline(in, key);
            key = Core::trimmed(key);
            list = Core::split(key, ' ');
            continue; // skip any spin-forbidden transitions
          }

          if (list.size() == 8) {
            wavenumbers = Core::lexicalCast<double>(list[1]).value_or(0.0);
            // convert to eV
            m_electronicTransitions.push_back(wavenumbers / 8065.544);
            m_electronicIntensities.push_back(
              Core::lexicalCast<double>(list[3]).value_or(0.0));
          } else if (list.size() == 11) {
            // directly use the eV
            m_electronicTransitions.push_back(
              Core::lexicalCast<double>(list[3]).value_or(0.0));
            m_electronicIntensities.push_back(
              Core::lexicalCast<double>(list[6]).value_or(0.0));
          }

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
          if (list.size() < 2)
            break; // hit the blank line
        }
        m_currentMode = NotParsing;
        break;
      }
      case ECD: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');

        while (!key.empty()) {
          // should have 7 columns
          if (list.size() < 7) {
            getline(in, key);
            key = Core::trimmed(key);
            list = Core::split(key, ' ');
            continue; // skip any spin-forbidden transitions
          }

          if (list.size() == 7)
            m_electronicRotations.push_back(
              Core::lexicalCast<double>(list[3]).value_or(0.0));
          else if (list.size() == 10)
            m_electronicRotations.push_back(
              Core::lexicalCast<double>(list[6]).value_or(0.0));

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
          if (list.size() < 2)
            break; // hit the blank line
        }
        m_currentMode = NotParsing;
        break;
      }
      case NMR: {
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        // default to filling m_nmrShifts with zeros
        m_nmrShifts.resize(m_atomNums.size(), 0.0);
        while (!key.empty()) {
          // should have 4 columns
          if (list.size() != 4) {
            break;
          }

          // e.g.  1  C  0.0000  0.0000  0.0000  0.0000
          int atomIndex = Core::lexicalCast<int>(list[0]).value_or(0);
          double shift = Core::lexicalCast<double>(list[2]).value_or(0.0);
          // ignore the anisotropy for now
          m_nmrShifts[atomIndex] = shift;

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }

        m_currentMode = NotParsing;
        break;
      }
      case GTO: {
        //            // should start at the first newGTO
        if (key.empty())
          break;
        nGTOs = 0;
        list = Core::split(key, ' ');
        int nShells;
        // init all vectors etc.
        m_basisAtomLabel.clear();
        m_orcaNumShells.resize(0);
        m_basisFunctions.resize(0);
        m_orcaShellTypes.resize(0);

        m_a.resize(0);
        m_c.resize(0);
        m_shellNums.resize(0);
        m_shellTypes.resize(0);
        m_shelltoAtom.resize(0);
        while (Core::trimmed(list[0]) == "NewGTO") {
          m_basisAtomLabel.push_back(Core::trimmed(list[1]));

          getline(in, key);
          key = Core::trimmed(key);

          list = Core::split(key, ' ');

          nShells = 0;
          m_basisFunctions.push_back(
            new std::vector<std::vector<Eigen::Vector2d>*>);
          shellFunctions.resize(0);
          shellTypes.resize(0);
          while (Core::trimmed(list[0]) != "end;") {

            int nFunc =
              Core::lexicalCast<int>(Core::trimmed(list[1])).value_or(0);
            shellTypes.push_back(orbitalIdx(Core::trimmed(list[0])));
            shellFunctions.push_back(nFunc);
            m_basisFunctions.at(nGTOs)->push_back(
              new std::vector<Eigen::Vector2d>(nFunc));

            for (int i = 0; i < nFunc; i++) {
              getline(in, key);
              key = Core::trimmed(key);

              list = Core::split(key, ' ');
              m_basisFunctions.at(nGTOs)->at(nShells)->at(i).x() =
                Core::lexicalCast<double>(list[1]).value_or(0.0); // exponent
              m_basisFunctions.at(nGTOs)->at(nShells)->at(i).y() =
                Core::lexicalCast<double>(list[2]).value_or(0.0); // coeff
            }

            nShells++;
            getline(in, key);
            key = Core::trimmed(key);

            list = Core::split(key, ' ');
          }
          m_orcaShellTypes.push_back(
            std::vector<GaussianSet::orbital>(shellTypes.size()));
          m_orcaShellTypes.at(nGTOs) = shellTypes;
          m_orcaNumShells.push_back(std::vector<int>(shellFunctions.size()));
          m_orcaNumShells.at(nGTOs) = shellFunctions;
          nGTOs++;

          getline(in, key);
          getline(in, key);
          getline(in, key);
          key = Core::trimmed(key);

          list = Core::split(key, ' ');
          if (list.size() == 0)
            break; // unexpected structure - suppose no more NewGTOs
        }

        // create input for gaussian basisset
        int nBasis = nGTOs;
        int nAtoms = m_atomLabel.size();
        m_currentAtom = 0;
        for (int i = 0; i < nAtoms; i++) {
          m_currentAtom++;
          for (int j = 0; j < nBasis; j++) {
            if (m_atomLabel.at(i) == m_basisAtomLabel.at(j)) {
              for (unsigned int k = 0; k < m_orcaNumShells.at(j).size(); k++) {
                for (int l = 0; l < m_orcaNumShells.at(j).at(k); l++) {
                  m_a.push_back(m_basisFunctions.at(j)->at(k)->at(l).x());
                  m_c.push_back(m_basisFunctions.at(j)->at(k)->at(l).y());
                }
                m_shellNums.push_back(m_orcaNumShells.at(j).at(k));
                m_shellTypes.push_back(m_orcaShellTypes.at(j).at(k));
                m_shelltoAtom.push_back(m_currentAtom);
              }
              break;
            }
          }
        }
        m_currentMode = NotParsing;
        break;
      }
      case MO: {

        m_MOcoeffs.clear();      // if the orbitals were punched multiple times
        m_orbitalEnergy.clear(); // we can get the energies here
        std::vector<std::string> orcaOrbitals;

        while (!Core::trimmed(key).empty()) {
          // currently reading the sequence number
          getline(in, key); // energies
          list = Core::split(key, ' ');
          // convert these all to double and add to m_orbitalEnergy
          for (unsigned int i = 0; i < list.size(); i++) {
            // convert from Hartree to eV
            m_orbitalEnergy.push_back(
              Core::lexicalCast<double>(list[i]).value_or(0.0) * HARTREE_TO_EV);
          }

          getline(in, key); // occupations
          getline(in, key); // skip -----------
          getline(in, key); // now we've got coefficients

          // coefficients are optionally a -, one or two digits, a decimal
          // point, and then 6 digits or just one or two digits a decimal point
          // and then 6 digits we can use a regex to split the line
          regex rx("[-]?[0-9]{1,2}[.][0-9]{6}");

          auto key_begin = std::sregex_iterator(key.begin(), key.end(), rx);
          auto key_end = std::sregex_iterator();
          list.clear();
          for (std::sregex_iterator i = key_begin; i != key_end; ++i) {
            list.push_back(i->str());
          }

          numColumns = list.size();
          columns.resize(numColumns);
          while (list.size() > 0) {
            // get the '2s' or '1dx2y2' piece from the line
            // so we can re-order the orbitals later
            std::vector<std::string> pieces = Core::split(key, ' ');
            orcaOrbitals.push_back(pieces[1]);

            for (unsigned int i = 0; i < numColumns; ++i) {
              columns[i].push_back(
                Core::lexicalCast<double>(list[i]).value_or(0.0));
            }

            getline(in, key);
            key_begin = std::sregex_iterator(key.begin(), key.end(), rx);
            key_end = std::sregex_iterator();
            list.clear();
            for (std::sregex_iterator i = key_begin; i != key_end; ++i) {
              list.push_back(i->str());
            }

            if (list.size() != numColumns)
              break;

          } // ok, we've finished one batch of MO coeffs
          // now reorder the p orbitals from "orcaStyle" (pz, px,py)
          // to expected Avogadro (px,py,pz)
          std::size_t idx = 0;
          while (idx < orcaOrbitals.size()) {
            if (Core::contains(orcaOrbitals.at(idx), "pz")) {
              for (unsigned int i = 0; i < numColumns; i++) {
                if (idx + 1 >= columns[i].size())
                  break;
                std::swap(columns[i].at(idx), columns[i].at(idx + 1));
              }
              idx++;
              for (unsigned int i = 0; i < numColumns; i++) {
                if (idx + 1 >= columns[i].size())
                  break;
                std::swap(columns[i].at(idx), columns[i].at(idx + 1));
              }
              idx++;
              idx++;
            } else {
              idx++;
            }
          }

          // Now we need to re-order the MO coeffs, so we insert one MO at a
          // time
          for (unsigned int i = 0; i < numColumns; ++i) {
            numRows = columns[i].size();
            for (unsigned int j = 0; j < numRows; ++j) {
              m_MOcoeffs.push_back(columns[i][j]);
            }
          }
          columns.clear();
          orcaOrbitals.clear();

        } // finished parsing MOs
        if (m_MOcoeffs.size() != numRows * numRows) {
          m_orcaSuccess = false;
        }
        m_numBasisFunctions = numRows;
        if (m_openShell) {
          // TODO: parse both alpha and beta orbitals
          m_BetaMOcoeffs.clear(); // if the orbitals were punched multiple times
          m_betaOrbitalEnergy.clear(); // we can get the energies here
          getline(in, key);
          while (!Core::trimmed(key).empty()) {
            // currently reading the sequence number
            getline(in, key); // energies

            list = Core::split(key, ' ');
            // convert these all to double and add to m_orbitalEnergy
            for (unsigned int i = 0; i < list.size(); i++) {
              // convert from Hartree to eV
              m_orbitalEnergy.push_back(
                Core::lexicalCast<double>(list[i]).value_or(0.0) *
                HARTREE_TO_EV);
            }

            getline(in, key); // symmetries
            getline(in, key); // skip -----------
            getline(in, key); // now we've got coefficients

            regex rx("[-]?[0-9]{1,2}[.][0-9]{6}");
            auto key_begin = std::sregex_iterator(key.begin(), key.end(), rx);
            auto key_end = std::sregex_iterator();
            list.clear();
            for (std::sregex_iterator i = key_begin; i != key_end; ++i) {
              list.push_back(i->str());
            }

            numColumns = list.size();
            columns.resize(numColumns);
            while (list.size() > 0) {
              // get the '2s' or '1dx2y2' piece from the line
              // so we can re-order the orbitals later
              std::vector<std::string> pieces = Core::split(key, ' ');
              orcaOrbitals.push_back(pieces[1]);

              for (unsigned int i = 0; i < numColumns; ++i) {
                columns[i].push_back(
                  Core::lexicalCast<double>(list[i]).value_or(0.0));
              }

              getline(in, key);
              auto inner_key_begin =
                std::sregex_iterator(key.begin(), key.end(), rx);
              auto inner_key_end = std::sregex_iterator();
              list.clear();
              for (std::sregex_iterator i = inner_key_begin; i != inner_key_end;
                   ++i) {
                list.push_back(i->str());
              }

              if (list.size() != numColumns)
                break;

            } // ok, we've finished one batch of MO coeffs
            // now reorder the p orbitals from "orcaStyle" (pz, px,py) to
            // expected Avogadro (px,py,pz)

            std::size_t idx = 0;
            while (idx < orcaOrbitals.size()) {
              if (Core::contains(orcaOrbitals.at(idx), "pz")) {
                for (unsigned int i = 0; i < numColumns; i++) {
                  if (idx + 1 >= columns[i].size())
                    break;
                  std::swap(columns[i].at(idx), columns[i].at(idx + 1));
                }
                idx++;
                for (unsigned int i = 0; i < numColumns; i++) {
                  if (idx + 1 >= columns[i].size())
                    break;
                  std::swap(columns[i].at(idx), columns[i].at(idx + 1));
                }
                idx++;
                idx++;
              } else {
                idx++;
              }
            }

            // Now we need to re-order the MO coeffs, so we insert one MO at a
            // time
            for (unsigned int i = 0; i < numColumns; ++i) {
              numRows = columns[i].size();
              for (unsigned int j = 0; j < numRows; ++j) {
                m_BetaMOcoeffs.push_back(columns[i][j]);
              }
            }
            columns.clear();
            orcaOrbitals.clear();

            if (Core::trimmed(key).empty())
              getline(in, key); // skip the blank line after the MOs
          }                     // finished parsing 2nd. MOs
          if (m_MOcoeffs.size() != numRows * numRows) {
            m_orcaSuccess = false;
          }
          m_numBasisFunctions = numRows;
        }

        m_currentMode = NotParsing;
        break;
      }
      default:;
    } // end switch
  }   // end if (mode)
}

void ORCAOutput::load(GaussianSet* basis)
{
  // Now load up our basis set
  basis->setElectronCount(m_electrons);

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  int nSP = 0; // number of SP shells
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes.at(i) == GaussianSet::SP) {
      // SP orbital type - currently have to unroll into two shells
      int tmpGTO = nGTO;
      int s = basis->addBasis(m_shelltoAtom.at(i) - 1, GaussianSet::S);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGto(s, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom.at(i) - 1, GaussianSet::P);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGto(p, m_csp.at(nSP), m_a.at(tmpGTO));
        ++tmpGTO;
        ++nSP;
      }
    } else {
      int b = basis->addBasis(m_shelltoAtom.at(i) - 1, m_shellTypes.at(i));
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGto(b, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
    }
  }

  // Now to load in the MO coefficients
  if (m_MOcoeffs.size())
    basis->setMolecularOrbitals(m_MOcoeffs);
  if (m_BetaMOcoeffs.size())
    basis->setMolecularOrbitals(m_BetaMOcoeffs, Core::BasisSet::Beta);

  if (m_orbitalEnergy.size())
    basis->setMolecularOrbitalEnergy(m_orbitalEnergy);
  if (m_betaOrbitalEnergy.size())
    basis->setMolecularOrbitalEnergy(m_betaOrbitalEnergy, Core::BasisSet::Beta);

  // TODO: set orbital symmetries

  m_homo = ceil(m_electrons / 2.0);
  basis->generateDensityMatrix();
}

GaussianSet::orbital ORCAOutput::orbitalIdx(std::string txt)
{
  if (txt == "S")
    return GaussianSet::S;
  if (txt == "SP")
    return GaussianSet::SP;
  if (txt == "P")
    return GaussianSet::P;
  if (txt == "D")
    return GaussianSet::D5; //// orca only uses Spherical - 5 d components
  if (txt == "D5")
    return GaussianSet::D5;
  if (txt == "F")
    return GaussianSet::F7; //// orca only uses Spherical - 7 f components
  if (txt == "F7")
    return GaussianSet::F7;
  if (txt == "G")
    return GaussianSet::G9; //// orca only uses Spherical - 9 g components
  if (txt == "G9")
    return GaussianSet::G9;
  if (txt == "H")
    return GaussianSet::H11; //// orca only uses Spherical - 11 h
                             /// components
  if (txt == "H11")
    return GaussianSet::H11;
  if (txt == "I")
    return GaussianSet::I13; //// orca only uses Spherical - 13 i
                             /// components
  if (txt == "I13")
    return GaussianSet::I13;
  return GaussianSet::UU;
}

} // namespace Avogadro::QuantumIO
