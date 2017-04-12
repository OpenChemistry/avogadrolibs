/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2008-2009 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gaussianfchk.h"

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

GaussianFchk::GaussianFchk() : m_scftype(Rhf)
{
}

GaussianFchk::~GaussianFchk()
{
}

std::vector<std::string> GaussianFchk::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.push_back("fchk");
  return extensions;
}

std::vector<std::string> GaussianFchk::mimeTypes() const
{
  return std::vector<std::string>();
}

bool GaussianFchk::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  while (!in.eof())
    processLine(in);

  GaussianSet* basis = new GaussianSet;

  int nAtom = 0;
  for (unsigned int i = 0; i < m_aPos.size(); i += 3) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_aNums[nAtom++]));
    a.setPosition3d(Vector3(m_aPos[i] * BOHR_TO_ANGSTROM,
                            m_aPos[i + 1] * BOHR_TO_ANGSTROM,
                            m_aPos[i + 2] * BOHR_TO_ANGSTROM));
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);
  return true;
}

void GaussianFchk::processLine(std::istream& in)
{
  // First truncate the line, remove trailing white space and check any line of
  // the required length. We are looking for keyword lines of the form,
  // Charge                                     I                0
  // If we are in any other kind of block that is not known skip through until
  // we find a recognized block.
  string line;
  if (!getline(in, line) || line.size() < 44)
    return;

  string key = line.substr(0, 42);

  // cout << "Key:\t" << key << endl;
  key = Core::trimmed(key);

  string tmp = line.substr(43);
  vector<string> list = Core::split(tmp, ' ');

  // Big switch statement checking for various things we are interested in
  if (Core::contains(key, "RHF")) {
    m_scftype = Rhf;
  } else if (Core::contains(key, "UHF")) {
    m_scftype = Uhf;
  } else if (key == "Number of atoms" && list.size() > 1) {
    cout << "Number of atoms = " << Core::lexicalCast<int>(list[1]) << endl;
  } else if (key == "Number of electrons" && list.size() > 1) {
    m_electrons = Core::lexicalCast<int>(list[1]);
  } else if (key == "Number of alpha electrons" && list.size() > 1) {
    m_electronsAlpha = Core::lexicalCast<int>(list[1]);
  } else if (key == "Number of beta electrons" && list.size() > 1) {
    m_electronsBeta = Core::lexicalCast<int>(list[1]);
  } else if (key == "Number of basis functions" && list.size() > 1) {
    m_numBasisFunctions = Core::lexicalCast<int>(list[1]);
    cout << "Number of basis functions = " << m_numBasisFunctions << endl;
  } else if (key == "Atomic numbers" && list.size() > 2) {
    m_aNums = readArrayI(in, Core::lexicalCast<int>(list[2]));
    if (static_cast<int>(m_aNums.size()) != Core::lexicalCast<int>(list[2]))
      cout << "Reading atomic numbers failed.\n";
    else
      cout << "Reading atomic numbers succeeded.\n";
  }
  // Now we get to the meat of it - coordinates of the atoms
  else if (key == "Current cartesian coordinates" && list.size() > 2) {
    m_aPos = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
  }
  // The real meat is here - basis sets etc!
  else if (key == "Shell types" && list.size() > 2) {
    m_shellTypes = readArrayI(in, Core::lexicalCast<int>(list[2]));
  } else if (key == "Number of primitives per shell" && list.size() > 2) {
    m_shellNums = readArrayI(in, Core::lexicalCast<int>(list[2]));
  } else if (key == "Shell to atom map" && list.size() > 2) {
    m_shelltoAtom = readArrayI(in, Core::lexicalCast<int>(list[2]));
  }
  // Now to get the exponents and coefficients(
  else if (key == "Primitive exponents" && list.size() > 2) {
    m_a = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
  } else if (key == "Contraction coefficients" && list.size() > 2) {
    m_c = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
  } else if (key == "P(S=P) Contraction coefficients" && list.size() > 2) {
    m_csp = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
  } else if (key == "Alpha Orbital Energies") {
    if (m_scftype == Rhf) {
      m_orbitalEnergy = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
      cout << "MO energies, n = " << m_orbitalEnergy.size() << endl;
    } else if (m_scftype == Uhf) {
      m_alphaOrbitalEnergy =
        readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
      cout << "Alpha MO energies, n = " << m_alphaOrbitalEnergy.size() << endl;
    }
  } else if (key == "Beta Orbital Energies") {
    if (m_scftype != Uhf) {
      cout << "UHF detected. Reassigning Alpha properties." << endl;
      m_scftype = Uhf;
      m_alphaOrbitalEnergy = m_orbitalEnergy;
      m_orbitalEnergy = vector<double>();

      m_alphaMOcoeffs = m_MOcoeffs;
      m_MOcoeffs = vector<double>();
    }

    m_betaOrbitalEnergy = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
    cout << "Beta MO energies, n = " << m_betaOrbitalEnergy.size() << endl;
  } else if (key == "Alpha MO coefficients" && list.size() > 2) {
    if (m_scftype == Rhf) {
      m_MOcoeffs = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
      if (static_cast<int>(m_MOcoeffs.size()) ==
          Core::lexicalCast<int>(list[2]))
        cout << "MO coefficients, n = " << m_MOcoeffs.size() << endl;
    } else if (m_scftype == Uhf) {
      m_alphaMOcoeffs = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
      if (static_cast<int>(m_alphaMOcoeffs.size()) ==
          Core::lexicalCast<int>(list[2]))
        cout << "Alpha MO coefficients, n = " << m_alphaMOcoeffs.size() << endl;
    } else {
      cout << "Error, alpha MO coefficients, n = " << m_MOcoeffs.size() << endl;
    }
  } else if (key == "Beta MO coefficients" && list.size() > 2) {
    m_betaMOcoeffs = readArrayD(in, Core::lexicalCast<int>(list[2]), 16);
    if (static_cast<int>(m_betaMOcoeffs.size()) ==
        Core::lexicalCast<int>(list[2]))
      cout << "Beta MO coefficients, n = " << m_betaMOcoeffs.size() << endl;
  } else if (key == "Total SCF Density" && list.size() > 2) {
    if (readDensityMatrix(in, Core::lexicalCast<int>(list[2]), 16))
      cout << "SCF density matrix read in " << m_density.rows() << endl;
    else
      cout << "Error reading in the SCF density matrix.\n";
  } else if (key == "Spin SCF Density" && list.size() > 2) {
    if (readSpinDensityMatrix(in, Core::lexicalCast<int>(list[2]), 16))
      cout << "SCF spin density matrix read in " << m_spinDensity.rows()
           << endl;
    else
      cout << "Error reading in the SCF spin density matrix.\n";
  }
}

void GaussianFchk::load(GaussianSet* basis)
{
  // Now load up our basis set
  basis->setElectronCount(m_electrons);
  // basis->setElectronCount(m_electronsAlpha, Core::GaussianSet::alpha);
  // basis->setElectronCount(m_electronsBeta, Core::GaussianSet::beta);

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes[i] == -1) {
      // SP orbital type - actually have to add two shells
      int s = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::S);
      int tmpGTO = nGTO;
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(s, m_c[nGTO], m_a[nGTO]);
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom[i] - 1, GaussianSet::P);
      for (int j = 0; j < m_shellNums[i]; ++j) {
        basis->addGto(p, m_csp[tmpGTO], m_a[tmpGTO]);
        ++tmpGTO;
      }
    } else {
      GaussianSet::orbital type;
      switch (m_shellTypes[i]) {
        case 0:
          type = GaussianSet::S;
          break;
        case 1:
          type = GaussianSet::P;
          break;
        case 2:
          type = GaussianSet::D;
          break;
        case -2:
          type = GaussianSet::D5;
          break;
        case 3:
          type = GaussianSet::F;
          break;
        case -3:
          type = GaussianSet::F7;
          break;
        case 4:
          type = GaussianSet::G;
          break;
        case -4:
          type = GaussianSet::G9;
          break;
        case 5:
          type = GaussianSet::H;
          break;
        case -5:
          type = GaussianSet::H11;
          break;
        case 6:
          type = GaussianSet::I;
          break;
        case -6:
          type = GaussianSet::I13;
          break;
        default:
          // If we encounter GTOs we do not understand, the basis is likely
          // invalid
          type = GaussianSet::UU;
          /// basis->setValid(false);
      }
      if (type != GaussianSet::UU) {
        int b = basis->addBasis(m_shelltoAtom[i] - 1, type);
        for (int j = 0; j < m_shellNums[i]; ++j) {
          basis->addGto(b, m_c[nGTO], m_a[nGTO]);
          ++nGTO;
        }
      }
    }
  }
  // Now to load in the MO coefficients
  if (basis->isValid()) {
    if (m_MOcoeffs.size())
      basis->setMolecularOrbitals(m_MOcoeffs);
    else
      cout << "Error no MO coefficients...\n";
    if (m_alphaMOcoeffs.size())
      basis->setMolecularOrbitals(m_alphaMOcoeffs, BasisSet::Alpha);
    if (m_betaMOcoeffs.size())
      basis->setMolecularOrbitals(m_betaMOcoeffs, BasisSet::Beta);
    if (m_density.rows())
      basis->setDensityMatrix(m_density);
    if (m_spinDensity.rows())
      basis->setSpinDensityMatrix(m_spinDensity);
  } else {
    cout << "Basis set is not valid!\n";
  }
}

vector<int> GaussianFchk::readArrayI(std::istream& in, unsigned int n)
{
  vector<int> tmp;
  tmp.reserve(n);
  bool ok(false);
  while (tmp.size() < n) {
    if (in.eof()) {
      cout << "GaussianFchk::readArrayI could not read all elements " << n
           << " expected " << tmp.size() << " parsed.\n";
      return tmp;
    }
    string line;
    if (getline(in, line), line.empty())
      return tmp;

    vector<string> list = Core::split(line, ' ');
    for (size_t i = 0; i < list.size(); ++i) {
      if (tmp.size() >= n) {
        cout << "Too many variables read in. File may be inconsistent. "
             << tmp.size() << " of " << n << endl;
        return tmp;
      }
      tmp.push_back(Core::lexicalCast<int>(list[i], ok));
      if (!ok) {
        cout << "Warning: problem converting string to integer: " << list[i]
             << " in GaussianFchk::readArrayI.\n";
        return tmp;
      }
    }
  }
  return tmp;
}

vector<double> GaussianFchk::readArrayD(std::istream& in, unsigned int n,
                                        int width)
{
  vector<double> tmp;
  tmp.reserve(n);
  bool ok(false);
  while (tmp.size() < n) {
    if (in.eof()) {
      cout << "GaussianFchk::readArrayD could not read all elements " << n
           << " expected " << tmp.size() << " parsed.\n";
      return tmp;
    }
    string line;
    if (getline(in, line), line.empty())
      return tmp;

    if (width == 0) { // we can split by spaces
      vector<string> list = Core::split(line, ' ');
      for (size_t i = 0; i < list.size(); ++i) {
        if (tmp.size() >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << tmp.size() << " of " << n << endl;
          return tmp;
        }
        tmp.push_back(Core::lexicalCast<double>(list[i], ok));
        if (!ok) {
          cout << "Warning: problem converting string to integer: " << list[i]
               << " in GaussianFchk::readArrayD.\n";
          return tmp;
        }
      }
    } else { // Q-Chem files use 16 character fields
      int maxColumns = 80 / width;
      for (int i = 0; i < maxColumns; ++i) {
        string substring = line.substr(i * width, width);
        if (static_cast<int>(substring.length()) != width)
          break;
        if (tmp.size() >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << tmp.size() << " of " << n << endl;
          return tmp;
        }
        tmp.push_back(Core::lexicalCast<double>(substring, ok));
        if (!ok) {
          cout << "Warning: problem converting string to double: " << substring
               << " in GaussianFchk::readArrayD.\n";
          return tmp;
        }
      }
    }
  }
  return tmp;
}

bool GaussianFchk::readDensityMatrix(std::istream& in, unsigned int n,
                                     int width)
{
  // This function reads in the lower triangular density matrix
  m_density.resize(m_numBasisFunctions, m_numBasisFunctions);
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  bool ok = false;
  while (cnt < n) {
    if (in.eof()) {
      cout << "GaussianFchk::readDensityMatrix could not read all elements "
           << n << " expected " << cnt << " parsed.\n";
      return false;
    }
    string line;
    if (getline(in, line), line.empty())
      return false;

    if (width == 0) { // we can split by spaces
      vector<string> list = Core::split(line, ' ');
      for (size_t k = 0; k < list.size(); ++k) {
        if (cnt >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << cnt << " of " << n << endl;
          return false;
        }
        // Read in lower half matrix
        m_density(i, j) = Core::lexicalCast<double>(list[k], ok);
        if (ok) { // Valid double converted, carry on
          ++j;
          ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        } else { // Invalid conversion of a string to double
          cout << "Warning: problem converting string to double: " << list.at(k)
               << "\nIn GaussianFchk::readDensityMatrix.\n";
          return false;
        }
      }
    } else { // Q-Chem files use 16-character fields
      int maxColumns = 80 / width;
      for (int c = 0; c < maxColumns; ++c) {
        string substring = line.substr(c * width, width);
        if (static_cast<int>(substring.length()) != width) {
          break;
        } else if (cnt >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << cnt << " of " << n << endl;
          return false;
        }
        // Read in lower half matrix
        m_density(i, j) = Core::lexicalCast<double>(substring, ok);
        if (ok) { // Valid double converted, carry on
          ++j;
          ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        } else { // Invalid conversion of a string to double
          cout << "Warning: problem converting string to double: " << substring
               << "\nIn GaussianFchk::readDensityMatrix.\n";
          return false;
        }
      }
    }
  }
  return true;
}
bool GaussianFchk::readSpinDensityMatrix(std::istream& in, unsigned int n,
                                         int width)
{
  // This function reads in the lower triangular density matrix
  m_spinDensity.resize(m_numBasisFunctions, m_numBasisFunctions);
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  bool ok = false;
  while (cnt < n) {
    if (in.eof()) {
      cout << "GaussianFchk::readSpinDensityMatrix could not read all elements "
           << n << " expected " << cnt << " parsed.\n";
      return false;
    }
    string line;
    if (getline(in, line), line.empty())
      return false;

    if (width == 0) { // we can split by spaces
      vector<string> list = Core::split(line, ' ');
      for (size_t k = 0; k < list.size(); ++k) {
        if (cnt >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << cnt << " of " << n << endl;
          return false;
        }
        // Read in lower half matrix
        m_spinDensity(i, j) = Core::lexicalCast<double>(list[k], ok);
        if (ok) { // Valid double converted, carry on
          ++j;
          ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        } else { // Invalid conversion of a string to double
          cout << "Warning: problem converting string to double: " << list[k]
               << "\nIn GaussianFchk::readDensityMatrix.\n";
          return false;
        }
      }
    } else { // Q-Chem files use 16-character fields
      int maxColumns = 80 / width;
      for (int c = 0; c < maxColumns; ++c) {
        string substring = line.substr(c * width, width);
        if (static_cast<int>(substring.length()) != width) {
          break;
        } else if (cnt >= n) {
          cout << "Too many variables read in. File may be inconsistent. "
               << cnt << " of " << n << endl;
          return false;
        }
        // Read in lower half matrix
        m_spinDensity(i, j) = Core::lexicalCast<double>(substring, ok);
        if (ok) { // Valid double converted, carry on
          ++j;
          ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        } else { // Invalid conversion of a string to double
          cout << "Warning: problem converting string to double: " << substring
               << "\nIn GaussianFchk::readSpinDensityMatrix.\n";
          return false;
        }
      }
    }
  }
  return true;
}

void GaussianFchk::outputAll()
{
  switch (m_scftype) {
    case Rhf:
      cout << "SCF type = RHF\n";
      break;
    case Uhf:
      cout << "SCF type = UHF\n";
      break;
    case Rohf:
      cout << "SCF type = ROHF\n";
      break;
    default:
      cout << "SCF type = Unknown\n";
  }
  cout << "Shell mappings:\n";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    cout << i << " : type = " << m_shellTypes.at(i)
         << ", number = " << m_shellNums.at(i)
         << ", atom = " << m_shelltoAtom.at(i) << endl;
  if (m_MOcoeffs.size()) {
    cout << "MO coefficients:\n";
    for (unsigned int i = 0; i < m_MOcoeffs.size(); ++i)
      cout << m_MOcoeffs.at(i) << "\t";
    cout << endl << endl;
  }
  if (m_alphaMOcoeffs.size()) {
    cout << "Alpha MO coefficients:\n";
    for (unsigned int i = 0; i < m_alphaMOcoeffs.size(); ++i)
      cout << m_alphaMOcoeffs.at(i) << "\t";
    cout << endl << endl;
  }
  if (m_betaMOcoeffs.size()) {
    cout << "Beta MO coefficients:\n";
    for (unsigned int i = 0; i < m_betaMOcoeffs.size(); ++i)
      cout << m_betaMOcoeffs.at(i) << "\t";
    cout << endl << endl;
  }
}
}
}
