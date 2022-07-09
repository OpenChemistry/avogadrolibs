/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "mopacaux.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <iostream>

using std::vector;
using std::string;
using std::cout;
using std::endl;

namespace Avogadro::QuantumIO {

using Core::Atom;
using Core::SlaterSet;

MopacAux::MopacAux()
{
}

MopacAux::~MopacAux()
{
}

std::vector<std::string> MopacAux::fileExtensions() const
{
  std::vector<std::string> extensions;
  extensions.emplace_back("aux");
  return extensions;
}

std::vector<std::string> MopacAux::mimeTypes() const
{
  return std::vector<std::string>();
}

bool MopacAux::read(std::istream& in, Core::Molecule& molecule)
{
  // Read the log file line by line, most sections are terminated by an empty
  // line, so they should be retained.
  while (!in.eof())
    processLine(in);

  auto* basis = new SlaterSet;

  for (unsigned int i = 0; i < m_atomPos.size(); ++i) {
    Atom a = molecule.addAtom(static_cast<unsigned char>(m_atomNums[i]));
    a.setPosition3d(m_atomPos[i]);
  }
  // Do simple bond perception.
  molecule.perceiveBondsSimple();
  molecule.setBasisSet(basis);
  basis->setMolecule(&molecule);
  load(basis);
  return true;
}

void MopacAux::processLine(std::istream& in)
{
  // First truncate the line, remove trailing white space and check
  string line;
  if (!getline(in, line) || Core::trimmed(line).empty())
    return;

  string key = Core::trimmed(line);

  // Big switch statement checking for various things we are interested in
  if (Core::contains(key, "ATOM_EL")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of atoms = " << tmp << endl;
    m_atomNums = readArrayElements(in, tmp);
  } else if (Core::contains(key, "AO_ATOMINDEX")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of atomic orbitals = " << tmp << endl;
    m_atomIndex = readArrayI(in, tmp);
    for (int & i : m_atomIndex)
      --i;
  } else if (Core::contains(key, "ATOM_SYMTYPE")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of atomic orbital types = " << tmp << endl;
    m_atomSym = readArraySym(in, tmp);
  } else if (Core::contains(key, "AO_ZETA")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of zeta values = " << tmp << endl;
    m_zeta = readArrayD(in, tmp);
  } else if (Core::contains(key, "ATOM_PQN")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of PQN values =" << tmp << endl;
    m_pqn = readArrayI(in, tmp);
  } else if (Core::contains(key, "NUM_ELECTRONS")) {
    vector<string> list = Core::split(line, '=');
    if (list.size() > 1) {
      m_electrons = Core::lexicalCast<int>(list[1]);
      cout << "Number of electrons = " << m_electrons << endl;
    }
  } else if (Core::contains(key, "ATOM_X_OPT:ANGSTROMS")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 4));
    cout << "Number of atomic coordinates = " << tmp << endl;
    m_atomPos = readArrayVec(in, tmp);
  } else if (Core::contains(key, "OVERLAP_MATRIX")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6));
    cout << "Size of lower half triangle of overlap matrix = " << tmp << endl;
    readOverlapMatrix(in, tmp);
  } else if (Core::contains(key, "EIGENVECTORS")) {
    // For large molecules the Eigenvectors counter overflows to [*****]
    // So just use the square of the m_atomIndex array
    //      QString tmp = key.mid(key.indexOf('[')+1, 6);
    cout << "Size of eigen vectors matrix = "
         << m_atomIndex.size() * m_atomIndex.size() << endl;
    readEigenVectors(in,
                     static_cast<int>(m_atomIndex.size() * m_atomIndex.size()));
  } else if (Core::contains(key, "TOTAL_DENSITY_MATRIX")) {
    int tmp = Core::lexicalCast<int>(key.substr(key.find('[') + 1, 6));
    cout << "Size of lower half triangle of density matrix = " << tmp << endl;
    readDensityMatrix(in, tmp);
  }
}

void MopacAux::load(SlaterSet* basis)
{
  if (m_atomPos.size() == 0) {
    cout << "No atoms found in .aux file. Bailing out." << endl;
    // basis->setIsValid(false);
    return;
  }
  // Now load up our basis set
  basis->addSlaterIndices(m_atomIndex);
  basis->addSlaterTypes(m_atomSym);
  basis->addZetas(m_zeta);
  basis->addPQNs(m_pqn);
  basis->setElectronCount(m_electrons);
  basis->addOverlapMatrix(m_overlap);
  basis->addEigenVectors(m_eigenVectors);
  basis->addDensityMatrix(m_density);
}

vector<int> MopacAux::readArrayElements(std::istream& in, unsigned int n)
{
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & i : list) {
      tmp.push_back(
        static_cast<int>(Core::Elements::atomicNumberFromSymbol(i)));
    }
  }
  return tmp;
}

vector<int> MopacAux::readArrayI(std::istream& in, unsigned int n)
{
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & i : list)
      tmp.push_back(Core::lexicalCast<int>(i));
  }
  return tmp;
}

vector<double> MopacAux::readArrayD(std::istream& in, unsigned int n)
{
  vector<double> tmp;
  while (tmp.size() < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & i : list)
      tmp.push_back(Core::lexicalCast<double>(i));
  }
  return tmp;
}

vector<int> MopacAux::readArraySym(std::istream& in, unsigned int n)
{
  int type;
  vector<int> tmp;
  while (tmp.size() < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & i : list) {
      if (i == "S")
        type = SlaterSet::S;
      else if (i == "PX")
        type = SlaterSet::PX;
      else if (i == "PY")
        type = SlaterSet::PY;
      else if (i == "PZ")
        type = SlaterSet::PZ;
      else if (i == "X2")
        type = SlaterSet::X2;
      else if (i == "XZ")
        type = SlaterSet::XZ;
      else if (i == "Z2")
        type = SlaterSet::Z2;
      else if (i == "YZ")
        type = SlaterSet::YZ;
      else if (i == "XY")
        type = SlaterSet::XY;
      else
        type = SlaterSet::UU;
      tmp.push_back(type);
    }
  }
  return tmp;
}

vector<Vector3> MopacAux::readArrayVec(std::istream& in, unsigned int n)
{
  vector<Vector3> tmp(n / 3);
  double* ptr = tmp[0].data();
  unsigned int cnt = 0;
  while (cnt < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & i : list)
      ptr[cnt++] = Core::lexicalCast<double>(i);
  }
  return tmp;
}

bool MopacAux::readOverlapMatrix(std::istream& in, unsigned int n)
{
  m_overlap.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first comment line...
  string line;
  getline(in, line);
  while (cnt < n) {
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & k : list) {
      // m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_overlap(i, j) = m_overlap(j, i) = Core::lexicalCast<double>(k);
      ++i;
      ++cnt;
      if (i == f) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++f;
        ++j;
      }
    }
  }
  return true;
}

bool MopacAux::readEigenVectors(std::istream& in, unsigned int n)
{
  m_eigenVectors.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  while (cnt < n) {
    string line;
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & k : list) {
      m_eigenVectors(i, j) = Core::lexicalCast<double>(k);
      ++i;
      ++cnt;
      if (i == m_zeta.size()) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++j;
      }
    }
  }
  return true;
}

bool MopacAux::readDensityMatrix(std::istream& in, unsigned int n)
{
  m_density.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first comment line...
  string line;
  getline(in, line);
  while (cnt < n) {
    getline(in, line);
    vector<string> list = Core::split(line, ' ');
    for (auto & k : list) {
      // m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_density(i, j) = m_density(j, i) = Core::lexicalCast<double>(k);
      ++i;
      ++cnt;
      if (i == f) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++f;
        ++j;
      }
    }
  }
  return true;
}

void MopacAux::outputAll()
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
}
