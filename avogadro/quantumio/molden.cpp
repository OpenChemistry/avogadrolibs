/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2010 Geoffrey R. Hutchison
  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "molden.h"

#include <avogadro/core/gaussianset.h>
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

MoldenFile::MoldenFile()
  : m_coordFactor(1.0), m_electrons(0), m_mode(Unrecognized)
{
}

MoldenFile::~MoldenFile()
{
}

std::vector<std::string> MoldenFile::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.push_back("mold");
  extensions.push_back("molf");
  extensions.push_back("molden");
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
  while (!in.eof())
    processLine(in);

  GaussianSet* basis = new GaussianSet;

  int nAtom = 0;
  for (unsigned int i = 0; i < m_aPos.size(); i += 3) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_aNums[nAtom++]));
    a.setPosition3d(Vector3(m_aPos[i], m_aPos[i + 1], m_aPos[i + 2]));
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);
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
  if (Core::contains(line, "[Atoms]")) {
    if (list.size() > 1 && Core::contains(list[1], "AU"))
      m_coordFactor = BOHR_TO_ANGSTROM_D;
    m_mode = Atoms;
  } else if (Core::contains(line, "[GTO]")) {
    m_mode = GTO;
  } else if (Core::contains(line, "[MO]")) {
    m_mode = MO;
  } else if (Core::contains(line, "[")) { // unknown section
    m_mode = Unrecognized;
  } else {
    // We are in a section, and must parse the lines in that section.
    string shell;
    GaussianSet::orbital shellType;

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
        }

        // Parse the molecular orbital coefficients.
        while (!line.empty() && !Core::contains(line, "=")) {
          list = Core::split(line, ' ');
          if (list.size() < 2)
            break;

          m_MOcoeffs.push_back(Core::lexicalCast<double>(list[1]));

          getline(in, line);
          line = Core::trimmed(line);
          list = Core::split(line, ' ');
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
}

void MoldenFile::outputAll()
{
  cout << "Shell mappings:\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    cout << i << ": type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << endl;
  cout << "MO coefficients:\n";
  for (unsigned int i = 0; i < m_MOcoeffs.size(); ++i)
    cout << m_MOcoeffs.at(i) << "\t";
  cout << endl;
}
}
}
