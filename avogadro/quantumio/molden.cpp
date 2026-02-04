/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molden.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iomanip>
#include <iostream>
#include <sstream>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::BasisSet;
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
  } else if (Core::contains(line, "[5D]")) {
    m_cartesianD = false;
  } else if (Core::contains(line, "[7F]")) {
    m_cartesianF = false;
  } else if (Core::contains(line, "[9G]")) {
    m_cartesianG = false;
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
        int atom = Core::lexicalCast<int>(list[0]).value_or(0);

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
          else if (shell == "d") {
            if (m_cartesianD)
              shellType = GaussianSet::D;
            else
              shellType = GaussianSet::D5;
          } else if (shell == "f") {
            if (m_cartesianF)
              shellType = GaussianSet::F;
            else
              shellType = GaussianSet::F7;
          } else if (shell == "g") {
            if (m_cartesianG)
              shellType = GaussianSet::G;
            else
              shellType = GaussianSet::G9;
          }
          // TODO if Molden ever supports h, i, j
          if (shellType != GaussianSet::UU) {
            m_shellTypes.push_back(shellType);
            m_shelltoAtom.push_back(atom);
          } else {
            return;
          }

          int numGTOs = Core::lexicalCast<int>(list[1]).value_or(0);
          m_shellNums.push_back(numGTOs);

          // Now read all the exponents and contraction coefficients.
          for (int gto = 0; gto < numGTOs; ++gto) {
            getline(in, line);
            line = Core::trimmed(line);
            list = Core::split(line, ' ');
            if (list.size() > 1) {
              m_a.push_back(Core::lexicalCast<double>(list[0]).value_or(0.0));
              m_c.push_back(Core::lexicalCast<double>(list[1]).value_or(0.0));
            }
            if (shellType == GaussianSet::SP && list.size() > 2)
              m_csp.push_back(Core::lexicalCast<double>(list[2]).value_or(0.0));
          }
          // Start reading the next shell.
          getline(in, line);
          line = Core::trimmed(line);
        }
      } break;

      case MO: {
        // Buffer for orbital header fields - we need to wait for Spin line
        // before committing, since Ene/Sym may appear before Spin
        double pendingEnergy = 0.0;
        bool havePendingEnergy = false;
        string pendingSymmetry;
        bool havePendingSymmetry = false;
        bool pendingSpinBeta = m_currentSpinBeta; // default to current state

        // Parse the occupation, spin, energy, etc (Occup, Spin, Ene).
        while (!line.empty() && Core::contains(line, "=")) {
          if (Core::contains(line, "Occup"))
            m_electrons += Core::lexicalCast<int>(list[1]).value_or(0);
          else if (Core::contains(line, "Ene")) {
            pendingEnergy = Core::lexicalCast<double>(list[1]).value_or(0.0) *
                            HARTREE_TO_EV_D;
            havePendingEnergy = true;
          } else if (Core::contains(line, "Spin")) {
            // Check for Beta spin - handle both "Spin= Beta" and "Spin=Beta"
            if (Core::contains(line, "Beta")) {
              pendingSpinBeta = true;
              m_openShell = true;
            } else {
              pendingSpinBeta = false;
            }
          } else if (Core::contains(line, "Sym")) {
            pendingSymmetry = list[1];
            havePendingSymmetry = true;
          }
          getline(in, line);
          line = Core::trimmed(line);
          list = Core::split(line, ' ');
        }

        // Now commit the buffered values with the correct spin
        m_currentSpinBeta = pendingSpinBeta;
        if (havePendingEnergy) {
          if (m_currentSpinBeta)
            m_betaOrbitalEnergy.push_back(pendingEnergy);
          else
            m_orbitalEnergy.push_back(pendingEnergy);
        }
        if (havePendingSymmetry) {
          if (m_currentSpinBeta)
            m_betaSymmetryLabels.push_back(pendingSymmetry);
          else
            m_symmetryLabels.push_back(pendingSymmetry);
        }

        // Parse the molecular orbital coefficients.
        while (!line.empty() && !Core::contains(line, "=") &&
               !Core::contains(line, "[")) {
          list = Core::split(line, ' ');
          if (list.size() < 2)
            break;

          if (m_currentSpinBeta)
            m_betaMOcoeffs.push_back(
              Core::lexicalCast<double>(list[1]).value_or(0.0));
          else
            m_MOcoeffs.push_back(
              Core::lexicalCast<double>(list[1]).value_or(0.0));

          // we might go too far ahead
          currentPos = in.tellg();
          getline(in, line);
          line = Core::trimmed(line);
          list = Core::split(line, ' ');
        }
        // go back one line
        in.seekg(currentPos);
      } break;

      case Frequencies:
        // Parse the frequencies.
        m_frequencies.clear();
        while (!line.empty() && !Core::contains(line, "[")) {
          line = Core::trimmed(line);
          m_frequencies.push_back(
            Core::lexicalCast<double>(line).value_or(0.0));
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

              m_vibDisplacements.back().push_back(
                Vector3(Core::lexicalCast<double>(list[0]).value_or(0.0) *
                          BOHR_TO_ANGSTROM_D,
                        Core::lexicalCast<double>(list[1]).value_or(0.0) *
                          BOHR_TO_ANGSTROM_D,
                        Core::lexicalCast<double>(list[2]).value_or(0.0) *
                          BOHR_TO_ANGSTROM_D));

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
          m_IRintensities.push_back(
            Core::lexicalCast<double>(list[0]).value_or(0.0));
          if (list.size() == 2)
            m_RamanIntensities.push_back(
              Core::lexicalCast<double>(list[1]).value_or(0.0));

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
  m_aNums.push_back(Core::lexicalCast<int>(list[2]).value_or(0));
  m_aPos.push_back(Core::lexicalCast<double>(list[3]).value_or(0.0) *
                   m_coordFactor);
  m_aPos.push_back(Core::lexicalCast<double>(list[4]).value_or(0.0) *
                   m_coordFactor);
  m_aPos.push_back(Core::lexicalCast<double>(list[5]).value_or(0.0) *
                   m_coordFactor);
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
      // adjust the shell types if needed
      if (!m_cartesianD && m_shellTypes[i] == GaussianSet::D)
        m_shellTypes[i] = GaussianSet::D5;
      else if (m_cartesianD && m_shellTypes[i] == GaussianSet::D5)
        m_shellTypes[i] = GaussianSet::D;

      if (!m_cartesianF && m_shellTypes[i] == GaussianSet::F)
        m_shellTypes[i] = GaussianSet::F7;
      else if (m_cartesianF && m_shellTypes[i] == GaussianSet::F7)
        m_shellTypes[i] = GaussianSet::F;

      if (!m_cartesianG && m_shellTypes[i] == GaussianSet::G)
        m_shellTypes[i] = GaussianSet::G9;
      else if (m_cartesianG && m_shellTypes[i] == GaussianSet::G9)
        m_shellTypes[i] = GaussianSet::G;

      int b = basis->addBasis(m_shelltoAtom[i] - 1, m_shellTypes[i]);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(b, m_c[nGTO], m_a[nGTO]);
        ++nGTO;
      }
    }
  }
  // Now to load in the MO coefficients
  if (m_openShell) {
    // Set SCF type to UHF for open-shell calculations
    basis->setScfType(Core::Uhf);

    // Alpha orbitals (stored in m_MOcoeffs)
    if (m_MOcoeffs.size())
      basis->setMolecularOrbitals(m_MOcoeffs, BasisSet::Alpha);
    if (m_orbitalEnergy.size())
      basis->setMolecularOrbitalEnergy(m_orbitalEnergy, BasisSet::Alpha);
    if (m_symmetryLabels.size())
      basis->setSymmetryLabels(m_symmetryLabels, BasisSet::Alpha);

    // Beta orbitals
    if (m_betaMOcoeffs.size())
      basis->setMolecularOrbitals(m_betaMOcoeffs, BasisSet::Beta);
    if (m_betaOrbitalEnergy.size())
      basis->setMolecularOrbitalEnergy(m_betaOrbitalEnergy, BasisSet::Beta);
    if (m_betaSymmetryLabels.size())
      basis->setSymmetryLabels(m_betaSymmetryLabels, BasisSet::Beta);
  } else {
    // Closed-shell (RHF) - use Paired type
    basis->setScfType(Core::Rhf);
    if (m_MOcoeffs.size())
      basis->setMolecularOrbitals(m_MOcoeffs);
    if (m_orbitalEnergy.size())
      basis->setMolecularOrbitalEnergy(m_orbitalEnergy);
    if (m_symmetryLabels.size())
      basis->setSymmetryLabels(m_symmetryLabels);
  }
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

bool MoldenFile::write(std::ostream& out, const Core::Molecule& molecule)
{
  // Set output precision for floating point numbers
  out << std::setprecision(10) << std::scientific;

  // Write the Molden format header
  out << "[Molden Format]\n";

  // Get the basis set if available
  const auto* basis = dynamic_cast<const GaussianSet*>(molecule.basisSet());

  // Check for spherical basis functions and write appropriate flags
  if (basis != nullptr) {
    // We need to check what types of shells are present
    std::vector<int> symmetry = basis->symmetry();
    bool hasD5 = false, hasF7 = false, hasG9 = false;

    for (int sym : symmetry) {
      if (sym == GaussianSet::D5)
        hasD5 = true;
      else if (sym == GaussianSet::F7)
        hasF7 = true;
      else if (sym == GaussianSet::G9)
        hasG9 = true;
    }

    if (hasD5)
      out << "[5D]\n";
    if (hasF7)
      out << "[7F]\n";
    if (hasG9)
      out << "[9G]\n";
  }

  // Write atoms section
  writeAtoms(out, molecule);

  // Write GTO basis set if available
  if (basis != nullptr) {
    writeGTO(out, basis);
    writeMO(out, basis);
  }

  // Write multiple coordinate sets if available
  if (molecule.coordinate3dCount() > 1) {
    writeGeometries(out, molecule);
  }

  // Write vibrational data if available
  if (molecule.vibrationFrequencies().size() > 0) {
    writeFrequencies(out, molecule);
  }

  return true;
}

void MoldenFile::writeAtoms(std::ostream& out, const Core::Molecule& molecule)
{
  out << "[Atoms] Angs\n";

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    unsigned char atomicNum = molecule.atomicNumber(i);
    Vector3 pos = molecule.atomPosition3d(i);

    // Format: element_name number atomic_number x y z
    out << std::left << std::setw(4) << Core::Elements::symbol(atomicNum)
        << std::right << std::setw(6) << (i + 1) << std::setw(6)
        << static_cast<int>(atomicNum) << "  " << std::setw(18) << pos.x()
        << std::setw(18) << pos.y() << std::setw(18) << pos.z() << "\n";
  }
}

void MoldenFile::writeGTO(std::ostream& out, const Core::GaussianSet* basis)
{
  out << "[GTO]\n";

  std::vector<int> symmetry = basis->symmetry();
  std::vector<unsigned int> atomIndices = basis->atomIndices();
  std::vector<unsigned int> gtoIndices = basis->gtoIndices();
  std::vector<double> gtoA = basis->gtoA();
  std::vector<double> gtoC = basis->gtoC();

  // Group shells by atom
  unsigned int currentAtom = UINT_MAX;
  for (unsigned int i = 0; i < symmetry.size(); ++i) {
    unsigned int atomIdx = atomIndices[i];

    // Start a new atom block if needed
    if (atomIdx != currentAtom) {
      if (currentAtom != UINT_MAX) {
        out << "\n"; // Blank line between atoms
      }
      currentAtom = atomIdx;
      out << (atomIdx + 1)
          << " 0\n"; // atom number (1-indexed) and unused field
    }

    // Get shell type string
    string shellType;
    int shellSym = symmetry[i];
    switch (shellSym) {
      case GaussianSet::S:
        shellType = "s";
        break;
      case GaussianSet::P:
        shellType = "p";
        break;
      case GaussianSet::D:
      case GaussianSet::D5:
        shellType = "d";
        break;
      case GaussianSet::F:
      case GaussianSet::F7:
        shellType = "f";
        break;
      case GaussianSet::G:
      case GaussianSet::G9:
        shellType = "g";
        break;
      case GaussianSet::H:
      case GaussianSet::H11:
        shellType = "h";
        break;
      case GaussianSet::I:
      case GaussianSet::I13:
        shellType = "i";
        break;
      default:
        shellType = "s"; // fallback
        break;
    }

    // Get the number of primitives in this shell
    unsigned int startGTO = gtoIndices[i];
    unsigned int endGTO =
      (i + 1 < gtoIndices.size()) ? gtoIndices[i + 1] : gtoA.size();
    unsigned int numPrimitives = endGTO - startGTO;

    out << shellType << " " << numPrimitives << " 1.00\n";

    // Write exponents and contraction coefficients
    for (unsigned int j = startGTO; j < endGTO; ++j) {
      out << "  " << std::setw(18) << gtoA[j] << std::setw(18) << gtoC[j]
          << "\n";
    }
  }
  out << "\n"; // Final blank line to end GTO section
}

void MoldenFile::writeMO(std::ostream& out, const Core::GaussianSet* basis)
{
  out << "[MO]\n";

  ScfType scfType = basis->scfType();
  bool isOpenShell = (scfType == Uhf || scfType == Rohf);

  // Helper lambda to write orbitals for a given electron type
  auto writeOrbitals = [&](BasisSet::ElectronType type,
                           const string& spinLabel) {
    Core::MatrixX moMatrix = basis->moMatrix(type);
    std::vector<double> energies = basis->moEnergy(type);
    std::vector<std::string> symLabels = basis->symmetryLabels(type);
    std::vector<unsigned char> occupancies = basis->moOccupancy(type);

    if (moMatrix.cols() == 0)
      return;

    unsigned int numMOs = moMatrix.cols();
    unsigned int numBasis = moMatrix.rows();

    for (unsigned int mo = 0; mo < numMOs; ++mo) {
      // Write symmetry label
      string symLabel = (mo < symLabels.size() && !symLabels[mo].empty())
                          ? symLabels[mo]
                          : "a1";
      out << " Sym= " << symLabel << "\n";

      // Write energy (convert from eV back to Hartree for Molden format)
      double energy =
        (mo < energies.size()) ? energies[mo] / HARTREE_TO_EV_D : 0.0;
      out << " Ene= " << std::setw(18) << energy << "\n";

      // Write spin
      out << " Spin= " << spinLabel << "\n";

      // Write occupation
      int occup = 0;
      if (mo < occupancies.size()) {
        occup = occupancies[mo];
      } else if (!isOpenShell) {
        // For closed shell, assume doubly occupied up to HOMO
        occup = (mo < basis->lumo(type)) ? 2 : 0;
      } else {
        // For open shell, assume singly occupied up to HOMO
        occup = (mo < basis->lumo(type)) ? 1 : 0;
      }
      out << " Occup= " << occup << "\n";

      // Write MO coefficients
      for (unsigned int bf = 0; bf < numBasis; ++bf) {
        out << std::setw(6) << (bf + 1) << std::setw(18) << moMatrix(bf, mo)
            << "\n";
      }
    }
  };

  if (isOpenShell) {
    // Write alpha and beta orbitals separately
    writeOrbitals(BasisSet::Alpha, "Alpha");
    writeOrbitals(BasisSet::Beta, "Beta");
  } else {
    // Write paired orbitals as Alpha (standard convention)
    writeOrbitals(BasisSet::Paired, "Alpha");
  }
}

void MoldenFile::writeFrequencies(std::ostream& out,
                                  const Core::Molecule& molecule)
{
  Core::Array<double> frequencies = molecule.vibrationFrequencies();
  Core::Array<double> irIntensities = molecule.vibrationIRIntensities();
  Core::Array<double> ramanIntensities = molecule.vibrationRamanIntensities();

  if (frequencies.size() == 0)
    return;

  // Write frequencies
  out << "[FREQ]\n";
  for (size_t i = 0; i < frequencies.size(); ++i) {
    out << std::setw(18) << frequencies[i] << "\n";
  }

  // Write coordinates for vibrations (in Bohr)
  out << "[FR-COORD]\n";
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    unsigned char atomicNum = molecule.atomicNumber(i);
    Vector3 pos = molecule.atomPosition3d(i) * ANGSTROM_TO_BOHR_D;

    out << std::left << std::setw(4) << Core::Elements::symbol(atomicNum)
        << std::right << std::setw(18) << pos.x() << std::setw(18) << pos.y()
        << std::setw(18) << pos.z() << "\n";
  }

  // Write normal mode displacements (in Bohr)
  out << "[FR-NORM-COORD]\n";
  for (size_t mode = 0; mode < frequencies.size(); ++mode) {
    out << "vibration " << (mode + 1) << "\n";
    Core::Array<Vector3> lx = molecule.vibrationLx(static_cast<int>(mode));
    for (size_t atom = 0; atom < lx.size(); ++atom) {
      // Convert from Angstrom to Bohr for Molden format
      Vector3 disp = lx[atom] * ANGSTROM_TO_BOHR_D;
      out << std::setw(18) << disp.x() << std::setw(18) << disp.y()
          << std::setw(18) << disp.z() << "\n";
    }
  }

  // Write intensities if available
  if (irIntensities.size() > 0) {
    out << "[INT]\n";
    for (size_t i = 0; i < irIntensities.size(); ++i) {
      out << std::setw(18) << irIntensities[i];
      if (i < ramanIntensities.size()) {
        out << std::setw(18) << ramanIntensities[i];
      }
      out << "\n";
    }
  }
}

void MoldenFile::writeGeometries(std::ostream& out,
                                 const Core::Molecule& molecule)
{
  size_t numCoordSets = molecule.coordinate3dCount();
  if (numCoordSets <= 1)
    return;

  out << "[GEOMETRIES] XYZ\n";

  for (size_t coordIdx = 0; coordIdx < numCoordSets; ++coordIdx) {
    Core::Array<Vector3> coords = molecule.coordinate3d(coordIdx);

    // Write number of atoms and a comment line (required for XYZ format)
    out << molecule.atomCount() << "\n";
    out << "Frame " << (coordIdx + 1) << "\n";

    for (Index i = 0; i < molecule.atomCount(); ++i) {
      unsigned char atomicNum = molecule.atomicNumber(i);
      Vector3 pos = (i < coords.size()) ? coords[i] : Vector3::Zero();

      out << std::left << std::setw(4) << Core::Elements::symbol(atomicNum)
          << std::right << std::setw(18) << pos.x() << std::setw(18) << pos.y()
          << std::setw(18) << pos.z() << "\n";
    }
  }
}

} // namespace Avogadro::QuantumIO
