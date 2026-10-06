/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gamessus.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::BasisSet;
using Core::GaussianSet;
using Core::Rhf;
using Core::Rohf;
using Core::Uhf;

GAMESSUSOutput::GAMESSUSOutput() : m_coordFactor(1.0), m_scftype(Rhf) {}

GAMESSUSOutput::~GAMESSUSOutput() {}

std::vector<std::string> GAMESSUSOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("gamout");
  extensions.emplace_back("gamess");
  return extensions;
}

std::vector<std::string> GAMESSUSOutput::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GAMESSUSOutput::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  string buffer;
  while (Core::getLine(in, buffer)) {
    if (Core::contains(buffer, "COORDINATES (BOHR)")) {
      readAtomBlock(in, molecule, false);
    } else if (Core::contains(buffer, "COORDINATES OF ALL ATOMS ARE (ANGS)")) {
      readAtomBlock(in, molecule, true);
    } else if (Core::contains(buffer, "ATOMIC BASIS SET")) {
      readBasisSet(in);
    } else if (Core::contains(buffer, "CHARGE OF MOLECULE")) {
      vector<string> parts = Core::split(buffer, '=');
      if (parts.size() == 2)
        molecule.setData("totalCharge",
                         Core::lexicalCast<int>(parts[1]).value_or(0));
    } else if (Core::contains(buffer, "SPIN MULTIPLICITY")) {
      vector<string> parts = Core::split(buffer, '=');
      if (parts.size() == 2)
        molecule.setData("totalSpinMultiplicity",
                         Core::lexicalCast<int>(parts[1]).value_or(1));
    } else if (Core::contains(buffer, "NUMBER OF ELECTRONS")) {
      vector<string> parts = Core::split(buffer, '=');
      if (parts.size() == 2)
        m_electrons = Core::lexicalCast<int>(parts[1]).value_or(0);
      else
        cout << "error" << buffer << endl;
    }
    /*else if (Core::contains(buffer, "NUMBER OF OCCUPIED ORBITALS (ALPHA)")) {
      cout << "Found alpha orbitals\n";
    }
    else if (Core::contains(buffer, "NUMBER OF OCCUPIED ORBITALS (BETA )")) {
      cout << "Found alpha orbitals\n";
    }
    else if (Core::contains(buffer, "SCFTYP=")) {
      cout << "Found SCF type\n";
    }*/
    else if (Core::contains(buffer, "EIGENVECTORS")) {
      if (!readEigenvectors(in))
        return false;
    }
  }

  // f functions and beyond need to be reordered
  if (!reorderMOs())
    return false;

  molecule.perceiveBondsSimple();
  molecule.perceiveBondOrders();
  auto* basis = new GaussianSet;
  if (!load(basis, molecule.atomCount())) {
    delete basis;
    return false;
  }
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);

  // outputAll();

  return true;
}

void GAMESSUSOutput::readAtomBlock(std::istream& in, Core::Molecule& molecule,
                                   bool angs)
{
  // We read the atom block in until it terminates with a blank line.
  double coordFactor = angs ? 1.0 : BOHR_TO_ANGSTROM_D;
  string buffer;

  bool atomsExist = molecule.atomCount() > 0;
  Index index = 0;
  //@TODO - store all the coordinates
  while (Core::getLine(in, buffer)) {
    if (Core::contains(buffer, "CHARGE") || Core::contains(buffer, "------"))
      continue;
    else if (buffer.length() == 0 || buffer == "\n") // Our work here is done.
      return;
    vector<string> parts = Core::split(buffer, ' ');
    if (parts.size() != 5) {
      appendError("Poorly formed atom line: " + buffer);
      return;
    }
    bool ok(false);
    Vector3 pos;
    auto atomicNumber(
      static_cast<unsigned char>(Core::lexicalCast<int>(parts[1], ok)));
    if (!ok)
      appendError("Failed to cast to int for atomic number: " + parts[1]);
    pos.x() = Core::lexicalCast<Real>(parts[2], ok) * coordFactor;
    if (!ok)
      appendError("Failed to cast to double for position: " + parts[2]);
    pos.y() = Core::lexicalCast<Real>(parts[3], ok) * coordFactor;
    if (!ok)
      appendError("Failed to cast to double for position: " + parts[3]);
    pos.z() = Core::lexicalCast<Real>(parts[4], ok) * coordFactor;
    if (!ok)
      appendError("Failed to cast to double for position: " + parts[4]);

    Atom atom;
    if (!atomsExist) {
      atom = molecule.addAtom(atomicNumber, pos);
    } else {
      atom = molecule.atom(index);
      atom.setPosition3d(pos);
      index++;
    }
  }
}

void GAMESSUSOutput::readBasisSet(std::istream& in)
{
  // Basic strategy is to use the number of parts in a line to determine the
  // type, where atom has 1 part, and a GTO has 5 (or 6 for SP/L). Termination
  // of the block when we hit the summary information at the end.
  string buffer;
  int currentAtom(0);
  bool header(true);
  while (Core::getLine(in, buffer)) {
    if (header) { // Skip the header lines until we hit the last header line.
      if (Core::contains(buffer, "SHELL"))
        header = false;
      continue;
    }
    vector<string> parts = Core::split(buffer, ' ');
    if (Core::contains(buffer, "TOTAL NUMBER OF BASIS SET SHELLS")) {
      // End of the basis set block.
      return;
    } else if (parts.size() == 1) {
      // Currently just incrememt the current atom, we should probably at least
      // verify the element matches in the future too.
      ++currentAtom;
    } else if (parts.size() == 5 || parts.size() == 6) {
      if (parts[1].size() != 1) {
        appendError("Error parsing basis set line, unrecognized type" +
                    parts[1]);
        continue;
      }
      // Determine the shell type.
      GaussianSet::orbital shellType(GaussianSet::UU);
      switch (parts[1][0]) {
        case 'S':
          shellType = GaussianSet::S;
          break;
        case 'L':
          shellType = GaussianSet::SP;
          break;
        case 'P':
          shellType = GaussianSet::P;
          break;
        case 'D':
          shellType = GaussianSet::D;
          break;
        case 'F':
          shellType = GaussianSet::F;
          break;
        default:
          shellType = GaussianSet::UU;
          appendError("Unrecognized shell type: " + parts[1]);
      }
      // Read in the rest of the shell, terminate when the number of tokens
      // is not 5 or 6 in a line.
      int numGTOs(0);
      while (parts.size() == 5 || parts.size() == 6) {
        ++numGTOs;
        m_a.push_back(Core::lexicalCast<double>(parts[3]).value_or(0.0));
        m_c.push_back(Core::lexicalCast<double>(parts[4]).value_or(0.0));
        if (shellType == GaussianSet::SP && parts.size() == 6)
          m_csp.push_back(Core::lexicalCast<double>(parts[5]).value_or(0.0));
        if (!Core::getLine(in, buffer))
          break;
        parts = Core::split(buffer, ' ');
      }
      // Now add this to our data structure.
      m_shellNums.push_back(numGTOs);
      m_shellTypes.push_back(shellType);
      m_shelltoAtom.push_back(currentAtom);
    }
  }
}

bool GAMESSUSOutput::readEigenvectors(std::istream& in)
{
  string buffer;
  Core::getLine(in, buffer);
  Core::getLine(in, buffer);
  Core::getLine(in, buffer);
  vector<string> parts = Core::split(buffer, ' ');
  vector<vector<double>> eigenvectors;
  bool ok(false);
  size_t numberOfMos(0);
  bool newBlock(true);
  while (!Core::contains(buffer, "END OF") ||
         Core::contains(buffer, "--------")) {
    // Any line with actual information in it will contain >= 5 parts.
    if (parts.size() > 5 && buffer.substr(0, 16) != "                ") {
      if (newBlock) {
        // Reorder the columns/rows, add them and then prepare
        for (auto& eigenvector : eigenvectors)
          for (double j : eigenvector)
            m_MOcoeffs.push_back(j);
        eigenvectors.clear();
        eigenvectors.resize(parts.size() - 4);
        numberOfMos += eigenvectors.size();
        newBlock = false;
      }
      // Every row in a block has one column per MO in the block.
      if (parts.size() - 4 > eigenvectors.size()) {
        appendError("Eigenvector row has more columns than its block: " +
                    buffer);
        return false;
      }
      for (size_t i = 0; i < parts.size() - 4; ++i) {
        eigenvectors[i].push_back(Core::lexicalCast<double>(parts[i + 4], ok));
        if (!ok)
          appendError("Failed to cast to double for eigenvector: " + parts[i]);
      }
    } else {
      // Note that we are either ending or entering a new block of orbitals.
      newBlock = true;
    }
    if (!Core::getLine(in, buffer))
      break;
    parts = Core::split(buffer, ' ');
  }
  m_nMOs = numberOfMos;
  for (auto& eigenvector : eigenvectors)
    for (double j : eigenvector)
      m_MOcoeffs.push_back(j);

  // Now we just need to transpose the matrix, as GAMESS uses a different order.
  // We know the number of columns (MOs), and the number of rows (primitives).
  if (eigenvectors.size() != numberOfMos * m_a.size())
    appendError("Incorrect number of eigenvectors loaded.");
  return true;
}

bool GAMESSUSOutput::load(GaussianSet* basis, Index atomCount)
{
  // Now load up our basis set
  basis->setElectronCount(m_electrons);

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  int nSP = 0; // number of SP shells
  // readBasisSet() fills these three in step, one entry per shell.
  if (m_shellNums.size() != m_shellTypes.size() ||
      m_shelltoAtom.size() != m_shellTypes.size()) {
    appendError("Inconsistent basis set shell data.");
    return false;
  }
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    // Shell atoms are numbered from one, in the order of the coordinates.
    if (m_shelltoAtom[i] < 1 ||
        static_cast<Index>(m_shelltoAtom[i]) > atomCount) {
      appendError("Basis set shell on an atom that was not read: " +
                  std::to_string(m_shelltoAtom[i]));
      return false;
    }
    const auto numGTOs = static_cast<size_t>(m_shellNums[i]);
    const auto firstGTO = static_cast<size_t>(nGTO);
    if (firstGTO + numGTOs > m_a.size() || firstGTO + numGTOs > m_c.size()) {
      appendError("Too few basis set primitives read.");
      return false;
    }
    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes[i] == GaussianSet::SP) {
      // Every SP primitive row also carries a P coefficient.
      if (static_cast<size_t>(nSP) + numGTOs > m_csp.size()) {
        appendError("SP shell is missing P contraction coefficients.");
        return false;
      }
      // SP orbital type - currently have to unroll into two shells
      int tmpGTO = nGTO;
      int s = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::S);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(s, m_c[nGTO], m_a[nGTO]);
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::P);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(p, m_csp[nSP], m_a[tmpGTO]);
        ++tmpGTO;
        ++nSP;
      }
    } else {
      int b = basis->addBasis(m_shelltoAtom[i] - 1, m_shellTypes[i]);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(b, m_c[nGTO], m_a[nGTO]);
        ++nGTO;
      }
    }
  }
  //    qDebug() << " loading MOs " << m_MOcoeffs.size();

  // Now to load in the MO coefficients
  if (m_MOcoeffs.size())
    basis->setMolecularOrbitals(m_MOcoeffs);
  if (m_alphaMOcoeffs.size())
    basis->setMolecularOrbitals(m_alphaMOcoeffs, BasisSet::Alpha);
  if (m_betaMOcoeffs.size())
    basis->setMolecularOrbitals(m_betaMOcoeffs, BasisSet::Beta);

  // generateDensity();
  // if (m_density.rows())
  // basis->setDensityMatrix(m_density);

  basis->setScfType(m_scftype);
  return true;
}

bool GAMESSUSOutput::reorderMOs()
{
  unsigned int GTOcounter = 0;
  for (int iMO = 0; iMO < m_nMOs; iMO++) {
    // loop over the basis set shells
    for (auto& m_shellType : m_shellTypes) {
      // The angular momentum of the shell
      // determines the number of primitive GTOs.
      // GAMESS always prints the full cartesian set.
      double yyy, zzz, xxy, xxz, yyx, yyz, zzx, zzy, xyz;
      unsigned int nPrimGTOs = 0;
      switch (m_shellType) {
        case GaussianSet::S:
          nPrimGTOs = 1;
          GTOcounter += nPrimGTOs;
          break;
        case GaussianSet::P:
          nPrimGTOs = 3;
          GTOcounter += nPrimGTOs;
          break;
        // L?
        case GaussianSet::D:
          nPrimGTOs = 6;
          GTOcounter += nPrimGTOs;
          break;
        case GaussianSet::F:
          nPrimGTOs = 10;
          if (GTOcounter + nPrimGTOs > m_MOcoeffs.size()) {
            appendError("Too few MO coefficients for the basis set.");
            return false;
          }
          // f functions are the first set to be reordered.
          // double xxx = m_MOcoeffs[GTOcounter];
          yyy = m_MOcoeffs[GTOcounter + 1];
          zzz = m_MOcoeffs[GTOcounter + 2];
          xxy = m_MOcoeffs[GTOcounter + 3];
          xxz = m_MOcoeffs[GTOcounter + 4];
          yyx = m_MOcoeffs[GTOcounter + 5];
          yyz = m_MOcoeffs[GTOcounter + 6];
          zzx = m_MOcoeffs[GTOcounter + 7];
          zzy = m_MOcoeffs[GTOcounter + 8];
          xyz = m_MOcoeffs[GTOcounter + 9];
          // xxx is unchanged
          m_MOcoeffs[GTOcounter + 1] = xxy; // xxy
          m_MOcoeffs[GTOcounter + 2] = xxz; // xxz
          m_MOcoeffs[GTOcounter + 3] = yyx; // xyy
          m_MOcoeffs[GTOcounter + 4] = xyz; // xyz
          m_MOcoeffs[GTOcounter + 5] = zzx; // xzz
          m_MOcoeffs[GTOcounter + 6] = yyy; // yyy
          m_MOcoeffs[GTOcounter + 7] = yyz; // yyz
          m_MOcoeffs[GTOcounter + 8] = zzy; // yzz
          m_MOcoeffs[GTOcounter + 9] = zzz; // zzz

          GTOcounter += nPrimGTOs;
          break;
        case GaussianSet::G:
          nPrimGTOs = 15;
          GTOcounter += nPrimGTOs;
          break;
        case GaussianSet::H:
          nPrimGTOs = 21;
          GTOcounter += nPrimGTOs;
          break;
        case GaussianSet::I:
          nPrimGTOs = 28;
          GTOcounter += nPrimGTOs;
          break;
        default:
          cout << "Basis set not handled - results may be incorrect.\n";
      }
    }
  }
  return true;
}

void GAMESSUSOutput::outputAll()
{
  switch (m_scftype) {
    case Rhf:
      cout << "SCF type = RHF" << endl;
      break;
    case Uhf:
      cout << "SCF type = UHF" << endl;
      break;
    case Rohf:
      cout << "SCF type = ROHF" << endl;
      break;
    default:
      cout << "SCF typ = Unknown" << endl;
  }
  cout << "Shell mappings\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    cout << i << ": type = " << m_shellTypes[i]
         << ", number = " << m_shellNums[i] << ", atom = " << m_shelltoAtom[i]
         << endl;
  }
  int nGTOs = 0;
  if (m_MOcoeffs.size() && m_nMOs > 0) {
    nGTOs = m_MOcoeffs.size() / m_nMOs;
    cout << m_nMOs << " MOs, " << nGTOs << " GTOs" << endl;
  }

  // Dump the first few coefficients of the first few MOs, bounded by both the
  // MO count and what was actually read.
  for (int iMO = 0; iMO < 10 && iMO < m_nMOs && nGTOs > 0; ++iMO) {
    const size_t start = static_cast<size_t>(iMO) * static_cast<size_t>(nGTOs);
    size_t end = start + 10;
    if (end > m_MOcoeffs.size())
      end = m_MOcoeffs.size();
    for (size_t i = start; i < end; ++i)
      cout << m_MOcoeffs[i] << "\t";
    cout << "\n";
  }

  if (m_alphaMOcoeffs.size())
    cout << "Alpha MO coefficients.\n";
  for (double m_alphaMOcoeff : m_alphaMOcoeffs)
    cout << m_alphaMOcoeff;
  if (m_betaMOcoeffs.size())
    cout << "Beta MO coefficients.\n";
  for (double m_betaMOcoeff : m_betaMOcoeffs)
    cout << m_betaMOcoeff;
  cout << std::flush;
}
} // namespace Avogadro::QuantumIO
