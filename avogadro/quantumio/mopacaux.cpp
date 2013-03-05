/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "mopacaux.h"

#include <avogadro/core/molecule.h>
#include <avogadro/quantum/slaterset.h>

#include <QtCore/QFile>
#include <QtCore/QStringList>
#include <QtCore/QDebug>

using std::vector;
using Eigen::Vector3d;

namespace Avogadro {
namespace QuantumIO {

MopacAux::MopacAux(QString filename, SlaterSet* basis)
{
  // Open the file for reading and process it
  QFile file(filename);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
    return;

  qDebug() << "File" << filename << "opened.";

  // Process the formatted checkpoint and extract all the information we need
  m_in.setDevice(&file);
  while (!m_in.atEnd()) {
    processLine();
  }

  // Now it should all be loaded load it into the basis set
  load(basis);
}

MopacAux::~MopacAux()
{
}

void MopacAux::processLine()
{
  // First truncate the line, remove trailing white space and check
  QString line = m_in.readLine();
  QString key = line;
  key = key.trimmed();
  //    QStringList list = tmp.split("=", QString::SkipEmptyParts);

  // Big switch statement checking for various things we are interested in
  if (key.contains("ATOM_CORE")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of atoms =" << tmp.toInt();
    m_atomNums = readArrayI(tmp.toInt());
  }
  else if (key.contains("AO_ATOMINDEX")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of atomic orbitals =" << tmp.toInt();
    m_atomIndex = readArrayI(tmp.toInt());
    for (unsigned int i = 0; i < m_atomIndex.size(); ++i) {
      --m_atomIndex[i];
    }
  }
  else if (key.contains("ATOM_SYMTYPE")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of atomic orbital types =" << tmp.toInt();
    m_atomSym = readArraySym(tmp.toInt());
  }
  else if (key.contains("AO_ZETA")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of zeta values =" << tmp.toInt();
    m_zeta = readArrayD(tmp.toInt());
  }
  else if (key.contains("ATOM_PQN")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of PQN values =" << tmp.toInt();
    m_pqn = readArrayI(tmp.toInt());
  }
  else if (key.contains("NUM_ELECTRONS")) {
    QString tmp = key.split('=').at(1);
    qDebug() << "Number of electrons =" << tmp.toInt();
    m_electrons = tmp.toInt();
  }
  else if (key.contains("ATOM_X_OPT:ANGSTROMS")) {
    QString tmp = key.mid(key.indexOf('[')+1, 4);
    qDebug() << "Number of atomic coordinates =" << tmp.toInt();
    m_atomPos = readArrayVec(tmp.toInt());
  }
  else if (key.contains("OVERLAP_MATRIX")) {
    QString tmp = key.mid(key.indexOf('[')+1, 6);
    qDebug() << "Size of lower half triangle of overlap matrix =" << tmp.toInt();
    readOverlapMatrix(tmp.toInt());
  }
  else if (key.contains("EIGENVECTORS")) {
    // For large molecules the Eigenvectors counter overflows to [*****]
    // So just use the square of the m_atomIndex array
    //      QString tmp = key.mid(key.indexOf('[')+1, 6);
    qDebug() << "Size of eigen vectors matrix ="
             << m_atomIndex.size() * m_atomIndex.size();
    readEigenVectors(static_cast<int>(m_atomIndex.size() * m_atomIndex.size()));
  }
  else if (key.contains("TOTAL_DENSITY_MATRIX")) {
    QString tmp = key.mid(key.indexOf('[')+1, 6);
    qDebug() << "Size of lower half triangle of density matrix =" << tmp.toInt();
    readDensityMatrix(tmp.toInt());
  }
}

void MopacAux::load(SlaterSet* basis)
{
  if (m_atomPos.size() == 0) {
    qWarning() << "No atoms found in .aux file. Bailing out.";
    basis->setIsValid(false);
    return;
  }
  // Now load up our basis set
  basis->addAtoms(m_atomPos);
  basis->addSlaterIndices(m_atomIndex);
  basis->addSlaterTypes(m_atomSym);
  basis->addZetas(m_zeta);
  basis->addPQNs(m_pqn);
  basis->setNumElectrons(m_electrons);
  basis->addOverlapMatrix(m_overlap);
  basis->addEigenVectors(m_eigenVectors);
  basis->addDensityMatrix(m_density);

  Core::Molecule &mol = basis->moleculeRef();
  if (m_atomPos.size() == m_atomNums.size()) {
    for (size_t i = 0; i < m_atomPos.size(); ++i) {
      Core::Atom a = mol.addAtom(static_cast<unsigned char>(m_atomNums[i]));
      a.setPosition3d(m_atomPos[i]);
    }
  }
  else {
    qWarning() << "Number of atomic numbers (" << m_atomNums.size()
               << ") does not equal the number of atomic positions ("
               << m_atomPos.size() << "). Not populating molecule.";
    basis->setIsValid(false);
  }
}

vector<int> MopacAux::readArrayI(unsigned int n)
{
  vector<int> tmp;
  while (tmp.size() < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int i = 0; i < list.size(); ++i)
      tmp.push_back(list.at(i).toInt());
  }
  return tmp;
}

vector<double> MopacAux::readArrayD(unsigned int n)
{
  vector<double> tmp;
  while (tmp.size() < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int i = 0; i < list.size(); ++i)
      tmp.push_back(list.at(i).toDouble());
  }
  return tmp;
}

vector<int> MopacAux::readArraySym(unsigned int n)
{
  int type;
  vector<int> tmp;
  while (tmp.size() < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int i = 0; i < list.size(); ++i) {
      if (list.at(i) == "S") type = SlaterSet::S;
      else if (list.at(i) == "PX") type = SlaterSet::PX;
      else if (list.at(i) == "PY") type = SlaterSet::PY;
      else if (list.at(i) == "PZ") type = SlaterSet::PZ;
      else if (list.at(i) == "X2") type = SlaterSet::X2;
      else if (list.at(i) == "XZ") type = SlaterSet::XZ;
      else if (list.at(i) == "Z2") type = SlaterSet::Z2;
      else if (list.at(i) == "YZ") type = SlaterSet::YZ;
      else if (list.at(i) == "XY") type = SlaterSet::XY;
      else type = SlaterSet::UU;
      tmp.push_back(type);
    }
  }
  return tmp;
}

vector<Vector3d> MopacAux::readArrayVec(unsigned int n)
{
  vector<Vector3d> tmp(n/3);
  double *ptr = tmp[0].data();
  unsigned int cnt = 0;
  while (cnt < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int i = 0; i < list.size(); ++i) {
      ptr[cnt++] = list.at(i).toDouble();
    }
  }
  return tmp;
}

bool MopacAux::readOverlapMatrix(unsigned int n)
{
  m_overlap.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first commment line...
  m_in.readLine();
  while (cnt < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int k = 0; k < list.size(); ++k) {
      //m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_overlap(i, j) = m_overlap(j, i) = list.at(k).toDouble();
      ++i; ++cnt;
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

bool MopacAux::readEigenVectors(unsigned int n)
{
  m_eigenVectors.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  while (cnt < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int k = 0; k < list.size(); ++k) {
      m_eigenVectors(i, j) = list.at(k).toDouble();
      ++i; ++cnt;
      if (i == m_zeta.size()) {
        // We need to move down to the next row and increment f - lower tri
        i = 0;
        ++j;
      }
    }
  }
  return true;
}

bool MopacAux::readDensityMatrix(unsigned int n)
{
  m_density.resize(m_zeta.size(), m_zeta.size());
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  // Skip the first commment line...
  m_in.readLine();
  while (cnt < n) {
    QString line = m_in.readLine();
    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int k = 0; k < list.size(); ++k) {
      //m_overlap.part<Eigen::SelfAdjoint>()(i, j) = list.at(k).toDouble();
      m_density(i, j) = m_density(j, i) = list.at(k).toDouble();
      ++i; ++cnt;
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
  qDebug() << "Shell mappings.";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    qDebug() << i << ": type =" << m_shellTypes.at(i)
             << ", number =" << m_shellNums.at(i)
             << ", atom =" << m_shelltoAtom.at(i);
  qDebug() << "MO coefficients.";
  for (unsigned int i = 0; i < m_MOcoeffs.size(); ++i)
    qDebug() << m_MOcoeffs.at(i);
}

}
}
