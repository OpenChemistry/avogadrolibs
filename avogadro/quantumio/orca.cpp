/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orca.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <algorithm>
#include <iostream>

using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Array;
using Core::Atom;
using Core::GaussianSet;

ORCAOutput::ORCAOutput() {}

ORCAOutput::~ORCAOutput() {}

std::vector<std::string> ORCAOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("log");
  extensions.emplace_back("out");
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

  // add the partial charges
  if (m_partialCharges.size() > 0) {
    for (auto it = m_partialCharges.begin(); it != m_partialCharges.end();
         ++it) {
      molecule.setPartialCharges(it->first, it->second);
    }
  }

  if (m_frequencies.size() > 0 &&
      m_frequencies.size() == m_vibDisplacements.size() &&
      m_frequencies.size() == m_IRintensities.size()) {
    molecule.setVibrationFrequencies(m_frequencies);
    molecule.setVibrationIRIntensities(m_IRintensities);
    molecule.setVibrationLx(m_vibDisplacements);
    if (m_RamanIntensities.size())
      molecule.setVibrationRamanIntensities(m_RamanIntensities);
  }

  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();

  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);

  return true;
}

void ORCAOutput::processLine(std::istream& in, GaussianSet* basis)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  string key = Core::trimmed(line);
  vector<string> list;
  int nGTOs = 0;
  float vibScaling = 1.0f;

  if (Core::contains(key, "CARTESIAN COORDINATES (A.U.)")) {
    m_coordFactor = 1.; // leave the coords in BOHR ....
    m_currentMode = Atoms;
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
        m_nGroups = Core::lexicalCast<int>(list[2]);
      } else {
        return;
      }
      getline(in, key); // skip blank line
      for (int i = 0; i < m_nGroups; ++i) {
        getline(in, key); // skip group information
      }
      getline(in, key); // skip blank line
      for (uint i = 0; i < m_atomNums.size(); ++i) {
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
  } else if (Core::contains(key, "TOTAL NUMBER OF BASIS SET")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (Core::contains(key, "NUMBER OF CARTESIAN GAUSSIAN BASIS")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (Core::contains(key, "Number of Electrons")) {
    list = Core::split(key, ' ');
    m_electrons = Core::lexicalCast<int>(list[5]);
  } else if (Core::contains(key, "SPIN UP ORBITALS") && !m_openShell) {
    m_openShell = true; // TODO
  } else if (Core::contains(key, "MOLECULAR ORBITALS")) {
    m_currentMode = MO;
    getline(in, key); //------------
  } else if (Core::contains(key, "ATOMIC CHARGES")) {
    m_currentMode = Charges;
    // figure out what type of charges we have
    list = Core::split(key, ' ');
    if (list.size() > 2) {
      m_chargeType = Core::trimmed(list[0]); // e.g. MULLIKEN or LOEWDIN
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
      vibScaling = Core::lexicalCast<float>(list[5]);
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
            Core::lexicalCast<double>(list[5]) * m_coordFactor,
            Core::lexicalCast<double>(list[6]) * m_coordFactor,
            Core::lexicalCast<double>(list[7]) * m_coordFactor);

          m_atomNums.push_back(Core::lexicalCast<int>(list[2]));
          m_atomPos.push_back(pos);
          m_atomLabel.push_back(Core::trimmed(list[1]));
          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }
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
          int atomIndex = Core::lexicalCast<int>(list[0]);
          double charge = Core::lexicalCast<double>(list[3]);
          charges(atomIndex, 0) = charge;

          getline(in, key);
          key = Core::trimmed(key);
          list = Core::split(key, ' ');
        }
        m_partialCharges[m_chargeType] = charges;
        m_currentMode = NotParsing;
        break;
      }
      case Frequencies: {
        // should start at the first frequency - include zeros
        if (key.empty())
          break;
        list = Core::split(key, ' ');
        while (!key.empty()) {
          if (list.size() != 3) {
            break;
          }
          // e.g. 0:         0.00 cm**-1
          double freq = Core::lexicalCast<double>(list[1]);
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
        vector<int> modeIndex;
        while (!key.empty()) {
          // first we get a set of column numbers
          // e.g. 1  2  3  4  5  6  7  8  9 10
          modeIndex.clear();
          for (unsigned int i = 0; i < list.size(); i++) {
            modeIndex.push_back(Core::lexicalCast<int>(list[i]));
          }
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
                Core::lexicalCast<double>(list[j + 1]);
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
          int index = Core::lexicalCast<double>(list[0]);
          double intensity = Core::lexicalCast<double>(list[3]);
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
          int index = Core::lexicalCast<double>(list[0]);
          if (m_RamanIntensities.size() == 0 && index > 0) {
            while (m_RamanIntensities.size() < index) {
              m_RamanIntensities.push_back(0.0);
            }
          }
          // index, frequency, activity, depolarization
          double activity = Core::lexicalCast<double>(list[2]);
          m_RamanIntensities.push_back(activity);

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

            int nFunc = Core::lexicalCast<int>(Core::trimmed(list[1]));
            shellTypes.push_back(orbitalIdx(Core::trimmed(list[0])));
            shellFunctions.push_back(nFunc);
            m_basisFunctions.at(nGTOs)->push_back(
              new std::vector<Eigen::Vector2d>(nFunc));

            for (int i = 0; i < nFunc; i++) {
              getline(in, key);
              key = Core::trimmed(key);

              list = Core::split(key, ' ');
              m_basisFunctions.at(nGTOs)->at(nShells)->at(i).x() =
                Core::lexicalCast<double>(list[1]); // exponent
              m_basisFunctions.at(nGTOs)->at(nShells)->at(i).y() =
                Core::lexicalCast<double>(list[2]); // coeff
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
              for (uint k = 0; k < m_orcaNumShells.at(j).size(); k++) {
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

        m_MOcoeffs.clear(); // if the orbitals were punched multiple times
        std::vector<std::string> orcaOrbitals;

        while (!Core::trimmed(key).empty()) {
          // currently reading the sequence number
          getline(in, key); // energies
          getline(in, key); // symmetries
          getline(in, key); // skip -----------
          getline(in, key); // now we've got coefficients

          /* TODO
          QRegExp rx("[.][0-9]{6}[0-9-]");
          while (rx.indexIn(key) != -1) { // avoid wrong splitting
            key.insert(rx.indexIn(key) + 1, " ");
          }
          */
          list = Core::split(key, ' ');

          numColumns = list.size() - 2;
          columns.resize(numColumns);
          while (list.size() > 2) {
            orcaOrbitals.push_back(list[1]);
            for (unsigned int i = 0; i < numColumns; ++i) {
              columns[i].push_back(Core::lexicalCast<double>(list[i + 2]));
            }

            getline(in, key);
            /*
            while (rx.indexIn(key) != -1) { // avoid wrong splitting
              key.insert(rx.indexIn(key) + 1, " ");
            }
            */

            list = Core::split(key, ' ');
            if (list.size() != numColumns + 2)
              break;

          } // ok, we've finished one batch of MO coeffs
          // now reorder the p orbitals from "orcaStyle" (pz, px,py)
          // to expected Avogadro (px,py,pz)
          int idx = 0;
          while (idx < orcaOrbitals.size()) {
            if (Core::contains(orcaOrbitals.at(idx), "pz")) {
              for (uint i = 0; i < numColumns; i++) {
                std::swap(columns[i].at(idx), columns[i].at(idx + 1));
              }
              idx++;
              for (uint i = 0; i < numColumns; i++) {
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
        if (m_openShell && m_useBeta) {
          m_MOcoeffs.clear(); // if the orbitals were punched multiple times
          vector<string> orcaOrbitals;
          getline(in, key);
          while (!Core::trimmed(key).empty()) {
            // currently reading the sequence number
            getline(in, key); // energies
            getline(in, key); // symmetries
            getline(in, key); // skip -----------
            getline(in, key); // now we've got coefficients

            /*/
            QRegExp rx("[.][0-9]{6}[0-9-]");
            while (rx.indexIn(key) != -1) { // avoid wrong splitting
              key.insert(rx.indexIn(key) + 1, " ");
            }
            */
            list = Core::split(key, ' ');
            numColumns = list.size() - 2;
            columns.resize(numColumns);
            while (list.size() > 2) {
              orcaOrbitals.push_back(list[1]);
              //                    columns.resize(numColumns);
              for (unsigned int i = 0; i < numColumns; ++i) {
                columns[i].push_back(Core::lexicalCast<double>(list[i + 2]));
              }

              getline(in, key);
              /*/
              while (rx.indexIn(key) != -1) { // avoid wrong splitting
                key.insert(rx.indexIn(key) + 1, " ");
              }
              */
              list = Core::split(key, ' ');
              if (list.size() != numColumns + 2)
                break;

            } // ok, we've finished one batch of MO coeffs
            // now reorder the p orbitals from "orcaStyle" (pz, px,py) to
            // expected Avogadro (px,py,pz)
            int idx = 0;
            while (idx < orcaOrbitals.size()) {
              if (Core::contains(orcaOrbitals.at(idx), "pz")) {
                for (uint i = 0; i < numColumns; i++) {
                  std::swap(columns[i].at(idx), columns[i].at(idx + 1));
                }
                idx++;
                for (uint i = 0; i < numColumns; i++) {
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
