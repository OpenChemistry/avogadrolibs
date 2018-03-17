/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Geoffrey R. Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gamessus.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::vector;
using std::string;
using std::cout;
using std::endl;

namespace Avogadro {
namespace QuantumIO {

using Core::Atom;
using Core::BasisSet;
using Core::GaussianSet;
using Core::Rhf;
using Core::Uhf;
using Core::Rohf;
using Core::Unknown;

GAMESSUSOutput::GAMESSUSOutput() : m_coordFactor(1.0), m_scftype(Rhf)
{
}

GAMESSUSOutput::~GAMESSUSOutput()
{
}

std::vector<std::string> GAMESSUSOutput::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.push_back("gamout");
  extensions.push_back("gamess");
  extensions.push_back("log");
  extensions.push_back("out");
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
  bool atomsRead(false);
  string buffer;
  while (getline(in, buffer)) {
    if (Core::contains(buffer, "COORDINATES (BOHR)")) {
      if (atomsRead)
        continue;
      atomsRead = true;
      readAtomBlock(in, molecule, false);
    } else if (Core::contains(buffer, "COORDINATES OF ALL ATOMS ARE (ANGS)")) {
      if (atomsRead)
        continue;
      atomsRead = true;
      readAtomBlock(in, molecule, true);
    } else if (Core::contains(buffer, "ATOMIC BASIS SET")) {
      readBasisSet(in);
    } else if (Core::contains(buffer, "NUMBER OF ELECTRONS")) {
      vector<string> parts = Core::split(buffer, '=');
      if (parts.size() == 2)
        m_electrons = Core::lexicalCast<int>(parts[1]);
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
      readEigenvectors(in);
    }
  }

  // f functions and beyond need to be reordered
  reorderMOs();

  molecule.perceiveBondsSimple();
  GaussianSet* basis = new GaussianSet;
  load(basis);
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
  while (getline(in, buffer)) {
    if (Core::contains(buffer, "CHARGE") || Core::contains(buffer, "------"))
      continue;
    else if (buffer == "\n") // Our work here is done.
      return;
    vector<string> parts = Core::split(buffer, ' ');
    if (parts.size() != 5) {
      appendError("Poorly formed atom line: " + buffer);
      return;
    }
    bool ok(false);
    Vector3 pos;
    unsigned char atomicNumber(
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
    Atom atom = molecule.addAtom(atomicNumber);
    atom.setPosition3d(pos);
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
  while (getline(in, buffer)) {
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
        m_a.push_back(Core::lexicalCast<double>(parts[3]));
        m_c.push_back(Core::lexicalCast<double>(parts[4]));
        if (shellType == GaussianSet::SP && parts.size() == 6)
          m_csp.push_back(Core::lexicalCast<double>(parts[5]));
        if (!getline(in, buffer))
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

void GAMESSUSOutput::readEigenvectors(std::istream& in)
{
  string buffer;
  getline(in, buffer);
  getline(in, buffer);
  getline(in, buffer);
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
        for (size_t i = 0; i < eigenvectors.size(); ++i)
          for (size_t j = 0; j < eigenvectors[i].size(); ++j)
            m_MOcoeffs.push_back(eigenvectors[i][j]);
        eigenvectors.clear();
        eigenvectors.resize(parts.size() - 4);
        numberOfMos += eigenvectors.size();
        newBlock = false;
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
    if (!getline(in, buffer))
      break;
    parts = Core::split(buffer, ' ');
  }
  m_nMOs = numberOfMos;
  for (size_t i = 0; i < eigenvectors.size(); ++i)
    for (size_t j = 0; j < eigenvectors[i].size(); ++j)
      m_MOcoeffs.push_back(eigenvectors[i][j]);

  // Now we just need to transpose the matrix, as GAMESS uses a different order.
  // We know the number of columns (MOs), and the number of rows (primitives).
  if (eigenvectors.size() != numberOfMos * m_a.size()) {
    appendError("Incorrect number of eigenvectors loaded.");
    return;
  }
}

void GAMESSUSOutput::load(GaussianSet* basis)
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
}

void GAMESSUSOutput::reorderMOs()
{
  unsigned int GTOcounter = 0;
  for (int iMO = 0; iMO < m_nMOs; iMO++) {
    // loop over the basis set shells
    for (unsigned int i = 0; i < m_shellTypes.size(); i++) {
      // The angular momentum of the shell
      // determines the number of primitive GTOs.
      // GAMESS always prints the full cartesian set.
      double yyy, zzz, xxy, xxz, yyx, yyz, zzx, zzy, xyz;
      unsigned int nPrimGTOs = 0;
      switch (m_shellTypes.at(i)) {
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
          // f functions are the first set to be reordered.
          // double xxx = m_MOcoeffs.at(GTOcounter);
          yyy = m_MOcoeffs.at(GTOcounter + 1);
          zzz = m_MOcoeffs.at(GTOcounter + 2);
          xxy = m_MOcoeffs.at(GTOcounter + 3);
          xxz = m_MOcoeffs.at(GTOcounter + 4);
          yyx = m_MOcoeffs.at(GTOcounter + 5);
          yyz = m_MOcoeffs.at(GTOcounter + 6);
          zzx = m_MOcoeffs.at(GTOcounter + 7);
          zzy = m_MOcoeffs.at(GTOcounter + 8);
          xyz = m_MOcoeffs.at(GTOcounter + 9);
          // xxx is unchanged
          m_MOcoeffs.at(GTOcounter + 1) = xxy; // xxy
          m_MOcoeffs.at(GTOcounter + 2) = xxz; // xxz
          m_MOcoeffs.at(GTOcounter + 3) = yyx; // xyy
          m_MOcoeffs.at(GTOcounter + 4) = xyz; // xyz
          m_MOcoeffs.at(GTOcounter + 5) = zzx; // xzz
          m_MOcoeffs.at(GTOcounter + 6) = yyy; // yyy
          m_MOcoeffs.at(GTOcounter + 7) = yyz; // yyz
          m_MOcoeffs.at(GTOcounter + 8) = zzy; // yzz
          m_MOcoeffs.at(GTOcounter + 9) = zzz; // zzz

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
    cout << i << ": type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << endl;
  }
  int nGTOs = 0;
  if (m_MOcoeffs.size()) {
    nGTOs = m_MOcoeffs.size() / m_nMOs;
    cout << m_nMOs << " MOs, " << nGTOs << " GTOs" << endl;
  }

  for (unsigned int iMO = 0; iMO < 10; iMO++) {
    for (unsigned int i = iMO * nGTOs; i < nGTOs * iMO + 10;
         ++i) // m_MOcoeffs.size(); ++i)
      cout << m_MOcoeffs.at(i) << "\t";
    cout << "\n";
  }

  if (m_alphaMOcoeffs.size())
    cout << "Alpha MO coefficients.\n";
  for (unsigned int i = 0; i < m_alphaMOcoeffs.size(); ++i)
    cout << m_alphaMOcoeffs.at(i);
  if (m_betaMOcoeffs.size())
    cout << "Beta MO coefficients.\n";
  for (unsigned int i = 0; i < m_betaMOcoeffs.size(); ++i)
    cout << m_betaMOcoeffs.at(i);
  cout << std::flush;
}
}
}
