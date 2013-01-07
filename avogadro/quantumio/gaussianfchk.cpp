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
#include <avogadro/quantum/gaussianset.h>

#include <QtCore/QFile>
#include <QtCore/QStringList>
#include <QtCore/QDebug>

using Eigen::Vector3d;
using std::vector;

namespace Avogadro {
namespace QuantumIO {

using Quantum::S;
using Quantum::SP;
using Quantum::P;
using Quantum::D;
using Quantum::D5;
using Quantum::F;
using Quantum::F7;
using Quantum::G;
using Quantum::G9;
using Quantum::H;
using Quantum::H11;
using Quantum::I;
using Quantum::I13;
using Quantum::UU;

using Quantum::orbital;

GaussianFchk::GaussianFchk(const QString &filename, GaussianSet* basis)
{
  // Open the file for reading and process it
  QFile* file = new QFile(filename);
  file->open(QIODevice::ReadOnly | QIODevice::Text);
  m_in = file;

  qDebug() << "File" << filename << "opened.";

  // Process the formatted checkpoint and extract all the information we need
  while (!m_in->atEnd()) {
    processLine();
  }

  // Now it should all be loaded load it into the basis set
  load(basis);

  delete file;
}

GaussianFchk::~GaussianFchk()
{
}

void GaussianFchk::processLine()
{
  // First truncate the line, remove trailing white space and check
  QString line = m_in->readLine();
  if (line.isEmpty())
    return;
  QString key = line;
  key.resize(42);
  key = key.trimmed();

  QString tmp = line.mid(43, 37);
  QStringList list = tmp.split(' ', QString::SkipEmptyParts);

  // Big switch statement checking for various things we are interested in
  if (key.contains("RHF")) {
        m_scftype=rhf;
  } else if (key.contains("UHF")) {
        m_scftype=uhf;
  } else if (key == "Number of atoms") {
    qDebug() << "Number of atoms =" << list.at(1).toInt();
  } else if (key == "Number of electrons") {
    m_electrons = list.at(1).toInt();
  } else if (key == "Number of alpha electrons") {
    m_electronsAlpha = list.at(1).toInt();
  } else if (key == "Number of beta electrons") {
    m_electronsBeta = list.at(1).toInt();
  } else if (key == "Number of basis functions") {
    m_numBasisFunctions = list.at(1).toInt();
    qDebug() << "Number of basis functions =" << m_numBasisFunctions;
  }
  else if (key == "Atomic numbers") {
    m_aNums = readArrayI(list.at(2).toInt());
    if (static_cast<int>(m_aNums.size()) != list.at(2).toInt())
      qDebug() << "Reading atomic numbers failed.";
    else
      qDebug() << "Reading atomic numbers succeeded.";
  }
  // Now we get to the meat of it - coordinates of the atoms
  else if (key == "Current cartesian coordinates")
    m_aPos = readArrayD(list.at(2).toInt(), 16);
  // The real meat is here - basis sets etc!
  else if (key == "Shell types")
    m_shellTypes = readArrayI(list.at(2).toInt());
  else if (key == "Number of primitives per shell")
    m_shellNums = readArrayI(list.at(2).toInt());
  else if (key == "Shell to atom map")
    m_shelltoAtom = readArrayI(list.at(2).toInt());
  // Now to get the exponents and coefficients(
  else if (key == "Primitive exponents")
    m_a = readArrayD(list.at(2).toInt(), 16);
  else if (key == "Contraction coefficients")
    m_c = readArrayD(list.at(2).toInt(), 16);
  else if (key == "P(S=P) Contraction coefficients")
    m_csp = readArrayD(list.at(2).toInt(), 16);
  else if (key == "Alpha Orbital Energies") {
    if (m_scftype == rhf) {
      m_orbitalEnergy = readArrayD(list.at(2).toInt(), 16);
      qDebug() << "MO energies, n =" << m_orbitalEnergy.size();
    } else if (m_scftype == uhf) {
      m_alphaOrbitalEnergy = readArrayD(list.at(2).toInt(), 16);
      qDebug() << "Alpha MO energies, n =" << m_alphaOrbitalEnergy.size();
    } else if (key == "Beta Orbital Energies") {
      m_betaOrbitalEnergy = readArrayD(list.at(2).toInt(), 16);
      qDebug() << "Beta MO energies, n =" << m_betaOrbitalEnergy.size();
    }
  }
  else if (key == "Alpha MO coefficients") {
    if (m_scftype == rhf) {
      m_MOcoeffs = readArrayD(list.at(2).toInt(), 16);
      if (static_cast<int>(m_MOcoeffs.size()) == list.at(2).toInt())
        qDebug() << "MO coefficients, n =" << m_MOcoeffs.size();
    } else if (m_scftype == uhf) {
      m_alphaMOcoeffs = readArrayD(list.at(2).toInt(), 16);
      if (static_cast<int>(m_alphaMOcoeffs.size()) == list.at(2).toInt())
        qDebug() << "Alpha MO coefficients, n =" << m_alphaMOcoeffs.size();
    } else
      qDebug() << "Error, MO coefficients, n =" << m_MOcoeffs.size();
  } else if (key == "Beta MO coefficients") {
      m_betaMOcoeffs = readArrayD(list.at(2).toInt(), 16);
      if (static_cast<int>(m_betaMOcoeffs.size()) == list.at(2).toInt())
        qDebug() << "Beta MO coefficients, n =" << m_betaMOcoeffs.size();
  }
  else if (key == "Total SCF Density") {
    if (readDensityMatrix(list.at(2).toInt(), 16))
      qDebug() << "SCF density matrix read in" << m_density.rows();
    else
      qDebug() << "Error reading in the SCF density matrix.";
  }
  else if (key == "Spin SCF Density") {
    if (readSpinDensityMatrix(list.at(2).toInt(), 16))
      qDebug() << "SCF spin density matrix read in" << m_spinDensity.rows();
    else
      qDebug() << "Error reading in the SCF spin density matrix.";
  }
}

void GaussianFchk::load(GaussianSet* basis)
{
  // Now load up our basis set
  basis->setNumElectrons(m_electrons);
  basis->setNumAlphaElectrons(m_electronsAlpha);
  basis->setNumBetaElectrons(m_electronsBeta);
  int nAtom = 0;
  for (unsigned int i = 0; i < m_aPos.size(); i += 3)
    basis->addAtom(Vector3d(m_aPos.at(i), m_aPos.at(i+1), m_aPos.at(i+2)),
                   m_aNums.at(nAtom++));

  qDebug() << "loading basis: " << m_shellTypes.size() << m_shellNums.size()
           << m_shelltoAtom.size() << m_a.size() << m_c.size() << m_csp.size();

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes.at(i) == -1)  {
      // SP orbital type - actually have to add two shells
      int s = basis->addBasis(m_shelltoAtom.at(i) - 1, S);
      int tmpGTO = nGTO;
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(s, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom.at(i) - 1, P);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(p, m_csp.at(tmpGTO), m_a.at(tmpGTO));
        ++tmpGTO;
      }
    }
    else {
      orbital type;
      switch (m_shellTypes.at(i)) {
      case 0:
        type = S;
        break;
      case 1:
        type = P;
        break;
      case 2:
        type = D;
        break;
      case -2:
        type = D5;
        break;
      case 3:
        type = F;
        break;
      case -3:
        type = F7;
        break;
      case 4:
        type = G;
        break;
      case -4:
        type = G9;
        break;
      case 5:
        type = H;
        break;
      case -5:
        type = H11;
        break;
      case 6:
        type = I;
        break;
      case -6:
        type = I13;
        break;
      default:
        // If we encounter GTOs we do not understand, the basis is likely invalid
        type = UU;
        basis->setIsValid(false);
      }
      if (type != UU) {
        int b = basis->addBasis(m_shelltoAtom.at(i) - 1, type);
        for (int j = 0; j < m_shellNums.at(i); ++j) {
          basis->addGTO(b, m_c.at(nGTO), m_a.at(nGTO));
          ++nGTO;
        }
      }
    }
  }
  // Now to load in the MO coefficients
  if (basis->isValid()) {
    if (m_MOcoeffs.size())
      basis->addMOs(m_MOcoeffs);
    if (m_alphaMOcoeffs.size())
      basis->addAlphaMOs(m_alphaMOcoeffs);
    if (m_betaMOcoeffs.size())
      basis->addBetaMOs(m_betaMOcoeffs);
    else
      qDebug() << "Error - no MO coefficients read in.";
    if (m_density.rows())
      basis->setDensityMatrix(m_density);
    if (m_spinDensity.rows())
      basis->setSpinDensityMatrix(m_spinDensity);
  }
}

vector<int> GaussianFchk::readArrayI(unsigned int n)
{
  vector<int> tmp;
  tmp.reserve(n);
  bool ok = false;
  while (tmp.size() < n) {
    if (m_in->atEnd()) {
      qDebug() << "GaussianFchk::readArrayI could not read all elements"
               << n << "expected" << tmp.size() << "parsed.";
      return tmp;
    }
    QString line = m_in->readLine();
    if (line.isEmpty())
      return tmp;

    QStringList list = line.split(' ', QString::SkipEmptyParts);
    for (int i = 0; i < list.size(); ++i) {
      if (tmp.size() >= n) {
        qDebug() << "Too many variables read in. File may be inconsistent."
                 << tmp.size() << "of" << n;
        return tmp;
      }
      tmp.push_back(list.at(i).toInt(&ok));
      if (!ok) {
        qDebug() << "Warning: problem converting string to integer:"
                 << list.at(i) << "in GaussianFchk::readArrayI.";
        return tmp;
      }
    }
  }
  return tmp;
}

vector<double> GaussianFchk::readArrayD(unsigned int n, int width)
{
  // FIXME Should return a bool and operate on a vector by reference
  vector<double> tmp;
  tmp.reserve(n);
  bool ok = false;
  while (tmp.size() < n) {
    if (m_in->atEnd()) {
      qDebug() << "GaussianFchk::readArrayD could not read all elements"
               << n << "expected" << tmp.size() << "parsed.";
      return tmp;
    }
    QString line = m_in->readLine();
    if (line.isEmpty())
      return tmp;

    if (width == 0) { // we can split by spaces
      QStringList list = line.split(' ', QString::SkipEmptyParts);
      for (int i = 0; i < list.size(); ++i) {
        if (tmp.size() >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << tmp.size() << "of" << n;
          return tmp;
        }
        tmp.push_back(list.at(i).trimmed().toDouble(&ok));
        if (!ok) {
          qDebug() << "Warning: problem converting string to double:"
                   << list.at(i) << "in GaussianFchk::readArrayD.";
          return tmp;
        }
      }
    }
    else { // Q-Chem files use 16 character fields
      int maxColumns = 80 / width;
      for (int i = 0; i < maxColumns; ++i) {
        QString substring = line.mid(i * width, width);
        if (substring.length() != width)
          break;
        if (tmp.size() >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << tmp.size() << "of" << n;
          return tmp;
        }
        tmp.push_back(substring.toDouble(&ok));
        if (!ok) {
          qDebug() << "Warning: problem converting string to double:"
                   << substring << "in GaussianFchk::readArrayD.";
          return tmp;
        }
      }
    }
  }
  return tmp;
}

bool GaussianFchk::readDensityMatrix(unsigned int n, int width)
{
  // This function reads in the lower triangular density matrix
  m_density.resize(m_numBasisFunctions, m_numBasisFunctions);
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  bool ok = false;
  while (cnt < n) {
    if (m_in->atEnd()) {
      qDebug() << "GaussianFchk::readDensityMatrix could not read all elements"
               << n << "expected" << cnt << "parsed.";
      return false;
    }
    QString line = m_in->readLine();
    if (line.isEmpty())
      return false;

    if (width == 0) { // we can split by spaces
      QStringList list = line.split(' ', QString::SkipEmptyParts);
      for (int k = 0; k < list.size(); ++k) {
        if (cnt >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << cnt << "of" << n;
          return false;
        }
        // Read in lower half matrix
        m_density(i, j) = list.at(k).toDouble(&ok);
        if (ok) { // Valid double converted, carry on
          ++j; ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        }
        else { // Invalid conversion of a string to double
          qDebug() << "Warning: problem converting string to double:"
                   << list.at(k) << "\nIn GaussianFchk::readDensityMatrix.";
          return false;
        }
      }
    }
    else { // Q-Chem files use 16-character fields
      int maxColumns = 80 / width;
      for (int c = 0; c < maxColumns; ++c) {
        QString substring = line.mid(c * width, width);
        if (substring.length() != width)
          break;
        else if (cnt >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << cnt << "of" << n;
          return false;
        }
        // Read in lower half matrix
        m_density(i, j) = substring.toDouble(&ok);
        if (ok) { // Valid double converted, carry on
          ++j; ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        }
        else { // Invalid conversion of a string to double
          qDebug() << "Warning: problem converting string to double:"
                   << substring << "\nIn GaussianFchk::readDensityMatrix.";
          return false;
        }
      }
    }
  }
  return true;
}
bool GaussianFchk::readSpinDensityMatrix(unsigned int n, int width)
{
  // This function reads in the lower triangular density matrix
  m_spinDensity.resize(m_numBasisFunctions, m_numBasisFunctions);
  unsigned int cnt = 0;
  unsigned int i = 0, j = 0;
  unsigned int f = 1;
  bool ok = false;
  while (cnt < n) {
    if (m_in->atEnd()) {
      qDebug() << "GaussianFchk::readSpinDensityMatrix could not read all elements"
               << n << "expected" << cnt << "parsed.";
      return false;
    }
    QString line = m_in->readLine();
    if (line.isEmpty())
      return false;

    if (width == 0) { // we can split by spaces
      QStringList list = line.split(' ', QString::SkipEmptyParts);
      for (int k = 0; k < list.size(); ++k) {
        if (cnt >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << cnt << "of" << n;
          return false;
        }
        // Read in lower half matrix
        m_spinDensity(i, j) = list.at(k).toDouble(&ok);
        if (ok) { // Valid double converted, carry on
          ++j; ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        }
        else { // Invalid conversion of a string to double
          qDebug() << "Warning: problem converting string to double:"
                   << list.at(k) << "\nIn GaussianFchk::readDensityMatrix.";
          return false;
        }
      }
    }
    else { // Q-Chem files use 16-character fields
      int maxColumns = 80 / width;
      for (int c = 0; c < maxColumns; ++c) {
        QString substring = line.mid(c * width, width);
        if (substring.length() != width)
          break;
        else if (cnt >= n) {
          qDebug() << "Too many variables read in. File may be inconsistent."
                   << cnt << "of" << n;
          return false;
        }
        // Read in lower half matrix
        m_spinDensity(i, j) = substring.toDouble(&ok);
        if (ok) { // Valid double converted, carry on
          ++j; ++cnt;
          if (j == f) {
            // We need to move down to the next row and increment f - lower tri
            j = 0;
            ++f;
            ++i;
          }
        }
        else { // Invalid conversion of a string to double
          qDebug() << "Warning: problem converting string to double:"
                   << substring << "\nIn GaussianFchk::readSpinDensityMatrix.";
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
    case rhf:
      qDebug() << "SCF type = RHF";
      break;
    case uhf:
      qDebug() << "SCF type = UHF";
      break;
    case rohf:
      qDebug() << "SCF type = ROHF";
      break;
    default:
      qDebug() << "SCF type = Unknown";
  }
  qDebug() << "Shell mappings.";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i)
    qDebug() << i << ": type =" << m_shellTypes.at(i)
             << ", number =" << m_shellNums.at(i)
             << ", atom =" << m_shelltoAtom.at(i);
  if (m_MOcoeffs.size())
    qDebug() << "MO coefficients.";
  for (unsigned int i = 0; i < m_MOcoeffs.size(); ++i)
    qDebug() << m_MOcoeffs.at(i);
  if (m_alphaMOcoeffs.size())
    qDebug() << "Alpha MO coefficients.";
  for (unsigned int i = 0; i < m_alphaMOcoeffs.size(); ++i)
    qDebug() << m_alphaMOcoeffs.at(i);
  if (m_betaMOcoeffs.size())
    qDebug() << "Beta MO coefficients.";
  for (unsigned int i = 0; i < m_betaMOcoeffs.size(); ++i)
    qDebug() << m_betaMOcoeffs.at(i);
}

}
}
