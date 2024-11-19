/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molden.h"

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::GaussianSet;

MoldenFile::MoldenFile()
  : m_coordFactor(1.0), m_electrons(0), m_mode(Unrecognized)
{
}

MoldenFile::~MoldenFile() {}

std::vector<std::string> MoldenFile::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("mold");
  extensions.emplace_back("molf");
  extensions.emplace_back("molden");
  return extensions;
}

std::vector<std::string> MoldenFile::mimeTypes() const
{
  return std::vector<std::string>();
}

bool MoldenFile::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  while (!in.eof() && in.good()) {
    processLine(in);
  }

  auto* basis = new GaussianSet;

  int nAtom = 0;
  for (unsigned int i = 0; i < m_aPos.size(); i += 3) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_aNums[nAtom++]));
    a.setPosition3d(Vector3(m_aPos[i], m_aPos[i + 1], m_aPos[i + 2]));
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);

  if (m_frequencies.size() > 0 &&
      m_frequencies.size() == m_vibDisplacements.size()) {
    molecule.setVibrationFrequencies(m_frequencies);
    molecule.setVibrationLx(m_vibDisplacements);

    // if we don't have intensities, set them all to zero
    if (m_IRintensities.size() != m_frequencies.size()) {
      m_IRintensities.resize(m_frequencies.size());
      for (unsigned int i = 0; i < m_frequencies.size(); i++)
        m_IRintensities[i] = 0.0;
    }
    molecule.setVibrationIRIntensities(m_IRintensities);

    if (m_RamanIntensities.size())
      molecule.setVibrationRamanIntensities(m_RamanIntensities);
  }

  return true;
}

void MoldenFile::processLine(std::istream& in)
{
  // First truncate the line, remove trailing white space and check for blanks.
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  vector<string> list = Core::split(line, ' ');

  // Big switch statement checking for various things we are interested in. The
  // Molden file format uses sections, each starts with a header line of the
  // form [Atoms], and the beginning of a new section denotes the end of the
  // last.
  if (Core::contains(line, "[Atoms]") || Core::contains(line, "[ATOMS]")) {
    if (list.size() > 1 && Core::contains(list[1], "AU"))
      m_coordFactor = BOHR_TO_ANGSTROM_D;
    m_mode = Atoms;
  } else if (Core::contains(line, "[GTO]")) {
    m_mode = GTO;
  } else if (Core::contains(line, "[MO]")) {
    m_mode = MO;
  } else if (Core::contains(line, "[FREQ]")) {
    m_mode = Frequencies;
  } else if (Core::contains(line, "[FR-NORM-COORD]")) {
    m_mode = VibrationalModes;
  } else if (Core::contains(line, "[INT]")) {
    m_mode = Intensities;
  } else if (Core::contains(line, "[")) { // unknown section
    m_mode = Unrecognized;
  } else {
    // We are in a section, and must parse the lines in that section.
    string shell;
    GaussianSet::orbital shellType;

    std::streampos currentPos = in.tellg();

    // Parsing a line of data in a section - what mode are we in?
    switch (m_mode) {
      case Atoms:
        readAtom(list);
        break;
      case GTO: {
        // TODO: detect dead files and make bullet-proof
        int atom = Core::lexicalCast<int>(list[0]);

        getline(in, line);
        line = Core::trimmed(line);
        while (!line.empty()) { // Read the shell types in this GTO.
          list = Core::split(line, ' ');
          if (list.size() < 1)
            break;
          shell = list[0];
          shellType = GaussianSet::UU;
          if (shell == "sp")
            shellType = GaussianSet::SP;
          else if (shell == "s")
            shellType = GaussianSet::S;
          else if (shell == "p")
            shellType = GaussianSet::P;
          else if (shell == "d")
            shellType = GaussianSet::D;
          else if (shell == "f")
            shellType = GaussianSet::F;
          else if (shell == "g")
            shellType = GaussianSet::G;

          if (shellType != GaussianSet::UU) {
            m_shellTypes.push_back(shellType);
            m_shelltoAtom.push_back(atom);
          } else {
            return;
          }

          int numGTOs = Core::lexicalCast<int>(list[1]);
          m_shellNums.push_back(numGTOs);

          // Now read all the exponents and contraction coefficients.
          for (int gto = 0; gto < numGTOs; ++gto) {
            getline(in, line);
            line = Core::trimmed(line);
            list = Core::split(line, ' ');
            if (list.size() > 1) {
              m_a.push_back(Core::lexicalCast<double>(list[0]));
              m_c.push_back(Core::lexicalCast<double>(list[1]));
            }
            if (shellType == GaussianSet::SP && list.size() > 2)
              m_csp.push_back(Core::lexicalCast<double>(list[2]));
          }
          // Start reading the next shell.
          getline(in, line);
          line = Core::trimmed(line);
        }
      } break;

      case MO:
        // Parse the occupation, spin, energy, etc (Occup, Spin, Ene).
        while (!line.empty() && Core::contains(line, "=")) {
          getline(in, line);
          line = Core::trimmed(line);
          list = Core::split(line, ' ');
          if (Core::contains(line, "Occup"))
            m_electrons += Core::lexicalCast<int>(list[1]);
          else if (Core::contains(line, "Ene"))
            m_orbitalEnergy.push_back(Core::lexicalCast<double>(list[1]));
          // TODO: track alpha beta spin
        }

        // Parse the molecular orbital coefficients.
        while (!line.empty() && !Core::contains(line, "=") &&
               !Core::contains(line, "[")) {
          list = Core::split(line, ' ');
          if (list.size() < 2)
            break;

          m_MOcoeffs.push_back(Core::lexicalCast<double>(list[1]));

          getline(in, line);
          line = Core::trimmed(line);
          list = Core::split(line, ' ');
        }
        // go back to previous line
        in.seekg(currentPos);
        break;

      case Frequencies:
        // Parse the frequencies.
        m_frequencies.clear();
        while (!line.empty() && !Core::contains(line, "[")) {
          line = Core::trimmed(line);
          m_frequencies.push_back(Core::lexicalCast<double>(line));
          currentPos = in.tellg();
          getline(in, line);
        }
        // go back to previous line
        in.seekg(currentPos);
        break;

      case VibrationalModes:
        // Parse the vibrational modes.
        // should be "vibration 1" etc.
        // then the normal mode displacements
        m_vibDisplacements.clear();
        // shouldn't be more than the number of frequencies
        while (!line.empty() && !Core::contains(line, "[")) {
          if (Core::contains(line, "vibration")) {
            m_vibDisplacements.push_back(Core::Array<Vector3>());
            getline(in, line);
            line = Core::trimmed(line);
            while (!line.empty() && !Core::contains(line, "[") &&
                   !Core::contains(line, "vibration")) {
              list = Core::split(line, ' ');
              if (list.size() < 3)
                break;

              m_vibDisplacements.back().push_back(Vector3(
                Core::lexicalCast<double>(list[0]) * BOHR_TO_ANGSTROM_D,
                Core::lexicalCast<double>(list[1]) * BOHR_TO_ANGSTROM_D,
                Core::lexicalCast<double>(list[2]) * BOHR_TO_ANGSTROM_D));

              currentPos = in.tellg();
              getline(in, line);
              line = Core::trimmed(line);
            }
          } else {
            // we shouldn't hit this, but better to be safe
            break;
          }

          // okay, we're either done reading
          // or we're at the next vibration
          if (m_vibDisplacements.size() == m_frequencies.size()) {
            // reset to make sure we don't miss any other sections
            // (e.g., intensities)
            in.seekg(currentPos);
            break;
          }
        }
        break;

      case Intensities:
        // could be just IR or two pieces including Raman
        while (!line.empty() && !Core::contains(line, "[")) {
          list = Core::split(line, ' ');
          m_IRintensities.push_back(Core::lexicalCast<double>(list[0]));
          if (list.size() == 2)
            m_RamanIntensities.push_back(Core::lexicalCast<double>(list[1]));

          if (m_IRintensities.size() == m_frequencies.size()) {
            // we're done
            break;
          }

          currentPos = in.tellg();
          getline(in, line);
          line = Core::trimmed(line);
        }
        break;
      default:
        break;
    }
  }
}

void MoldenFile::readAtom(const vector<string>& list)
{
  // element_name number atomic_number x y z
  if (list.size() < 6)
    return;
  m_aNums.push_back(Core::lexicalCast<int>(list[2]));
  m_aPos.push_back(Core::lexicalCast<double>(list[3]) * m_coordFactor);
  m_aPos.push_back(Core::lexicalCast<double>(list[4]) * m_coordFactor);
  m_aPos.push_back(Core::lexicalCast<double>(list[5]) * m_coordFactor);
}

void MoldenFile::load(GaussianSet* basis)
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
      int s = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::S);
      int p = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::P);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(s, m_c[nGTO], m_a[nGTO]);
        basis->addGto(p, m_csp[nSP], m_a[nGTO]);
        ++nSP;
        ++nGTO;
      }
    } else {
      int b = basis->addBasis(m_shelltoAtom[i] - 1, m_shellTypes[i]);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(b, m_c[nGTO], m_a[nGTO]);
        ++nGTO;
      }
    }
  }
  // Now to load in the MO coefficients
  if (m_MOcoeffs.size())
    basis->setMolecularOrbitals(m_MOcoeffs);
  if (m_orbitalEnergy.size())
    basis->setMolecularOrbitalEnergy(m_orbitalEnergy);
}

void MoldenFile::outputAll()
{
  cout << "Shell mappings:\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    cout << i << ": type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << endl;
  cout << "MO coefficients:\n";
  for (double m_MOcoeff : m_MOcoeffs)
    cout << m_MOcoeff << "\t";
  cout << endl;
}
} // namespace Avogadro::QuantumIO
