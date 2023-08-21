/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orca.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>
#include <algorithm>

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

  if (m_frequencies.size() > 0 &&
      m_frequencies.size() == m_vibDisplacements.size() &&
      m_frequencies.size() == m_intensities.size()) {
    molecule.setVibrationFrequencies(m_frequencies);
    molecule.setVibrationIRIntensities(m_intensities);
    molecule.setVibrationLx(m_vibDisplacements);
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
    m_openShell = true; // not yet implemented
  } else if (Core::contains(key, "MOLECULAR ORBITALS")) {
    m_currentMode = MO;
    getline(in, key); //------------
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
          Eigen::Vector3d pos(Core::lexicalCast<double>(list[5]) * m_coordFactor,
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
          m_orcaShellTypes.push_back(std::vector<GaussianSet::orbital>(shellTypes.size()));
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
    if (m_shellTypes.at(i) == Core::GaussianSet::SP) {
      // SP orbital type - currently have to unroll into two shells
      int tmpGTO = nGTO;
      int s = basis->addBasis(m_shelltoAtom.at(i) - 1, Core::GaussianSet::S);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGto(s, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom.at(i) - 1, Core::GaussianSet::P);
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

Core::GaussianSet::orbital ORCAOutput::orbitalIdx(std::string txt) {
    if (txt == "S") return Core::GaussianSet::S;
    if (txt == "SP") return Core::GaussianSet::SP;
    if (txt == "P") return Core::GaussianSet::P;
    if (txt == "D") return Core::GaussianSet::D5;  //// orca only uses Spherical - 5 d components
    if (txt == "D5") return Core::GaussianSet::D5;
    if (txt == "F") return Core::GaussianSet::F7;  //// orca only uses Spherical - 7 f components
    if (txt == "F7") return Core::GaussianSet::F7;
    if (txt == "G") return Core::GaussianSet::G9;  //// orca only uses Spherical - 9 g components
    if (txt == "G9") return Core::GaussianSet::G9;
    if (txt == "H") return Core::GaussianSet::H11; //// orca only uses Spherical - 11 h components
    if (txt == "H11") return Core::GaussianSet::H11;
    if (txt == "I") return Core::GaussianSet::I13; //// orca only uses Spherical - 13 i components
    if (txt == "I13") return Core::GaussianSet::I13;
    return Core::GaussianSet::UU;
}

} // namespace Avogadro::QuantumIO
