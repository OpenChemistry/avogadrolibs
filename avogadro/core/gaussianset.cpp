/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2008 Albert De Fusco
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gaussianset.h"

#include "molecule.h"

#include <cmath>
#include <iostream>

using std::cout;
using std::endl;

using std::vector;

namespace Avogadro {
namespace Core {

GaussianSet::GaussianSet() : m_numMOs(0), m_init(false)
{
  m_scfType = Rhf;
}

GaussianSet::~GaussianSet()
{
}

unsigned int GaussianSet::addBasis(unsigned int atom, orbital type)
{
  // Count the number of independent basis functions
  switch (type) {
    case S:
      ++m_numMOs;
      break;
    case P:
      m_numMOs += 3;
      break;
    case SP:
      m_numMOs += 4;
      break;
    case D:
      m_numMOs += 6;
      break;
    case D5:
      m_numMOs += 5;
      break;
    case F:
      m_numMOs += 10;
      break;
    case F7:
      m_numMOs += 7;
      break;
    default:
      // Should never hit here
      ;
  }
  m_init = false;

  // Add to the new data structure, delete the old soon
  m_symmetry.push_back(type);
  m_atomIndices.push_back(atom);
  return static_cast<unsigned int>(m_symmetry.size() - 1);
}

unsigned int GaussianSet::addGto(unsigned int basis, double c, double a)
{
  if (m_gtoIndices.size() == basis) {
    m_gtoIndices.push_back(static_cast<unsigned int>(m_gtoA.size()));
  } else if (m_gtoIndices.size() < basis) {
    cout << "Error, attempted to add a GTO for a basis too early. GTOs must be "
         << "added in order to ensure correct indexing.\n";
    return 69696969;
  }
  m_gtoA.push_back(a);
  m_gtoC.push_back(c);

  return static_cast<unsigned int>(m_gtoA.size() - 1);
}

void GaussianSet::setMolecularOrbitals(const vector<double>& MOs,
                                       ElectronType type)
{
  if (!m_numMOs)
    return;

  m_init = false;

  size_t index(0);
  if (type == Beta)
    index = 1;

  // Some programs don't output all MOs, so we take the amount of data
  // and divide by the number of atomic orbital functions.
  unsigned int columns = static_cast<unsigned int>(MOs.size()) / m_numMOs;
  // cout << " Add MOs: " << m_numMOs << columns << endl;

  m_moMatrix[index].resize(m_numMOs, columns);

  for (unsigned int j = 0; j < columns; ++j)
    for (unsigned int i = 0; i < m_numMOs; ++i)
      m_moMatrix[index].coeffRef(i, j) = MOs[i + j * m_numMOs];
}

void GaussianSet::setMolecularOrbitals(const vector<double>& MOs,
                                       ElectronType type, Index idx)
{
  if (!m_numMOs)
    return;

  size_t index = 0;
  if (type == Beta)
    index = 1;

  unsigned int columns = static_cast<unsigned int>(MOs.size()) / m_numMOs;

  MatrixX moMatrix;
  moMatrix.resize(m_numMOs, columns);

  for (unsigned int j = 0; j < columns; ++j)
    for (unsigned int i = 0; i < m_numMOs; ++i)
      moMatrix.coeffRef(i, j) = MOs[i + j * m_numMOs];

  if (idx <= m_moMatrixSet[index].size())
    m_moMatrixSet[index].resize(idx + 1);

  m_moMatrixSet[index][idx] = moMatrix;
}

bool GaussianSet::setActiveSetStep(int index)
{
  if (index >= static_cast<int>(m_moMatrixSet[0].size()) ||
      index >= static_cast<int>(m_moMatrixSet[1].size())) {
    return false;
  }

  if (index >= m_molecule->coordinate3dCount())
    return false;

  m_moMatrix[0] = m_moMatrixSet[0][index];
  m_moMatrix[1] = m_moMatrixSet[1][index];
  m_molecule->setCoordinate3d(index);
  return true;
}

void GaussianSet::setMolecularOrbitalEnergy(const vector<double>& energies,
                                            ElectronType type)
{
  if (type == Beta)
    m_moEnergy[1] = energies;
  else
    m_moEnergy[0] = energies;
}

void GaussianSet::setMolecularOrbitalOccupancy(const vector<unsigned char>& occ,
                                               ElectronType type)
{
  if (type == Beta)
    m_moOccupancy[1] = occ;
  else
    m_moOccupancy[0] = occ;
}

void GaussianSet::setMolecularOrbitalNumber(const vector<unsigned int>& nums,
                                            ElectronType type)
{
  if (type == Beta)
    m_moNumber[1] = nums;
  else
    m_moNumber[0] = nums;
}

bool GaussianSet::setDensityMatrix(const MatrixX& m)
{
  m_density.resize(m.rows(), m.cols());
  m_density = m;
  return true;
}

bool GaussianSet::setSpinDensityMatrix(const MatrixX& m)
{
  m_spinDensity.resize(m.rows(), m.cols());
  m_spinDensity = m;
  return true;
}

bool GaussianSet::generateDensityMatrix()
{
  // FIXME: Finish me!
  return true;
}

unsigned int GaussianSet::molecularOrbitalCount(ElectronType type)
{
  size_t index(0);
  if (type == Beta)
    index = 1;
  return static_cast<unsigned int>(m_moMatrix[index].rows());
}

void GaussianSet::outputAll(ElectronType type)
{
  size_t index(0);
  if (type == Beta)
    index = 1;

  // Can be called to print out a summary of the basis set as read in
  unsigned int numAtoms = static_cast<unsigned int>(m_molecule->atomCount());
  cout << "\nGaussian Basis Set\nNumber of atoms:" << numAtoms << endl;
  switch (m_scfType) {
    case Rhf:
      cout << "RHF orbitals" << endl;
      break;
    case Uhf:
      cout << "UHF orbitals" << endl;
      break;
    case Rohf:
      cout << "ROHF orbitals" << endl;
      break;
    default:
      cout << "Unknown orbitals" << endl;
  }

  initCalculation();

  cout << "Number of electrons = " << m_electrons[index] << endl;

  if (!isValid()) {
    cout << "Basis set is marked as invalid." << endl;
    return;
  }

  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    cout << i << "\tAtom Index: " << m_atomIndices[i]
         << "\tSymmetry: " << m_symmetry[i] << "\tMO Index: " << m_moIndices[i]
         << "\tGTO Index: " << m_gtoIndices[i] << endl;
  }
  cout << "Symmetry: " << m_symmetry.size()
       << "\tgtoIndices: " << m_gtoIndices.size()
       << "\tLast gtoIndex: " << m_gtoIndices[m_symmetry.size()]
       << "\ngto size: " << m_gtoA.size() << " " << m_gtoC.size() << " "
       << m_gtoCN.size() << endl;
  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
      case S:
        cout << "Shell " << i << "\tS\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](m_moIndices[i], 0) << endl;
        break;
      case P:
        cout << "Shell " << i << "\tP\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << endl;
        break;
      case D:
        cout << "Shell " << i << "\tD\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 3) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 4) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 5) << endl;
        break;
      case D5:
        cout << "Shell " << i << "\tD5\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 3) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 4) << endl;
        break;
      case F:
        cout << "Shell " << i << "\tF\n  MO 1";
        for (short j = 0; j < 10; ++j)
          cout << "\t" << m_moMatrix[index](0, m_moIndices[i] + j);
        cout << endl;
        break;
      case F7:
        cout << "Shell " << i << "\tF7\n  MO 1";
        for (short j = 0; j < 7; ++j)
          cout << "\t" << m_moMatrix[index](0, m_moIndices[i] + j);
        cout << endl;
        break;
      default:
        cout << "Error: unhandled type...\n";
    }
    unsigned int cIndex = m_gtoIndices[i];
    for (size_t j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
      if (j >= m_gtoA.size()) {
        cout << "Error, j is too large!" << j << m_gtoA.size() << endl;
        continue;
      }
      cout << cIndex << "\tc: " << m_gtoC[cIndex] << "\ta: " << m_gtoA[cIndex]
           << endl;
      ++cIndex;
    }
  }
  cout << "\nEnd of orbital data...\n";
}

bool GaussianSet::isValid()
{
  // TODO: Something useful here again - check the basis set makes sense...
  return true;
}

void GaussianSet::initCalculation()
{
  if (m_init)
    return;

  // This currently just involves normalising all contraction coefficients
  m_gtoCN.clear();

  // Initialise the new data structures that are hopefully more efficient
  unsigned int indexMO = 0;
  unsigned int skip = 0; // for unimplemented shells

  m_moIndices.resize(m_symmetry.size());
  // Add a final entry to the gtoIndices
  m_gtoIndices.push_back(static_cast<unsigned int>(m_gtoA.size()));
  for (unsigned int i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
      case S:
        m_moIndices[i] = indexMO++;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        // Normalization of the S-type orbitals (normalization used in JMol)
        // (8 * alpha^3 / pi^3)^0.25 * exp(-alpha * r^2)
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 0.75) * 0.71270547);
        }
        break;
      case P:
        m_moIndices[i] = indexMO;
        indexMO += 3;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        // Normalization of the P-type orbitals (normalization used in JMol)
        // (128 alpha^5 / pi^3)^0.25 * [x|y|z]exp(-alpha * r^2)
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.25) * 1.425410941);
          m_gtoCN.push_back(m_gtoCN.back());
          m_gtoCN.push_back(m_gtoCN.back());
        }
        break;
      case D:
        // Cartesian - 6 d components
        // Order in xx, yy, zz, xy, xz, yz
        m_moIndices[i] = indexMO;
        indexMO += 6;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        // Normalization of the P-type orbitals (normalization used in JMol)
        // xx|yy|zz: (2048 alpha^7/9pi^3)^0.25 [xx|yy|zz]exp(-alpha r^2)
        // xy|xz|yz: (2048 alpha^7/pi^3)^0.25 [xy|xz|yz]exp(-alpha r^2)
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.75) * 1.645922781);
          m_gtoCN.push_back(m_gtoCN.back());
          m_gtoCN.push_back(m_gtoCN.back());

          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 1.75) * 2.850821881);
          m_gtoCN.push_back(m_gtoCN.back());
          m_gtoCN.push_back(m_gtoCN.back());
        }
        break;
      case D5:
        // Spherical - 5 d components
        // Order in d0, d+1, d-1, d+2, d-2
        // Form d(z^2-r^2), dxz, dyz, d(x^2-y^2), dxy
        m_moIndices[i] = indexMO;
        indexMO += 5;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(
            m_gtoC[j] *
            pow(2048 * pow(m_gtoA[j], 7.0) / (9.0 * M_PI * M_PI * M_PI), 0.25));
          m_gtoCN.push_back(
            m_gtoC[j] *
            pow(2048 * pow(m_gtoA[j], 7.0) / (M_PI * M_PI * M_PI), 0.25));
          m_gtoCN.push_back(m_gtoCN.back());
          // I think this is correct but reaally need to check...
          m_gtoCN.push_back(
            m_gtoC[j] *
            pow(128 * pow(m_gtoA[j], 7.0) / (M_PI * M_PI * M_PI), 0.25));
          m_gtoCN.push_back(
            m_gtoC[j] *
            pow(2048 * pow(m_gtoA[j], 7.0) / (M_PI * M_PI * M_PI), 0.25));
        }
        break;
      case F:
        /*
         Thanks, Jmol
         Cartesian forms for f (l = 3) basis functions:
         Type         Normalization
         xxx          [(32768 * alpha^9) / (225 * pi^3))]^(1/4)
         xxy          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         xxz          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         xyy          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         xyz          [(32768 * alpha^9) / (1 * pi^3))]^(1/4)
         xzz          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         yyy          [(32768 * alpha^9) / (225 * pi^3))]^(1/4)
         yyz          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         yzz          [(32768 * alpha^9) / (9 * pi^3))]^(1/4)
         zzz          [(32768 * alpha^9) / (225 * pi^3))]^(1/4)

         Thank you, Python
                                     pi = 3.141592653589793
         (32768./225./(pi**3.))**(0.25) = 1.4721580892990938
         (32768./9./(pi**3.))**(0.25)   = 3.291845561298979
         (32768./(pi**3.))**(0.25)      = 5.701643762839922
         */
        {
          double norm1 = 1.4721580892990938;
          double norm2 = 3.291845561298979;
          double norm3 = 5.701643762839922;
          m_moIndices[i] = indexMO;
          indexMO += 10;
          m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
          for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // xxx
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xxy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xxz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xyy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm3); // xyz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xzz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // yyy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // yyz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // yzz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // zzz
          }
        }
        break;
      case F7: {
        // m-independent normalization factor
        // math.sqrt(2.**(3.+3./2.))/(math.pi**(3./4.))*math.sqrt(2.**3. / 15.)
        // same as norm1 above.
        double norm = 1.4721580892990935;
        m_moIndices[i] = indexMO;
        indexMO += 7;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); // 0
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //+1
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //-1
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //+2
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //-2
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //+3
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm); //-3
        }
      } break;
      case G:
        skip = 15;
        break;
      case G9:
        skip = 9;
        break;
      case H:
        skip = 21;
        break;
      case H11:
        skip = 11;
        break;
      case I:
        skip = 28;
        break;
      case I13:
        skip = 13;
        break;
      default:
        cout << "Basis set not handled - results may be incorrect.\n";
    }
    if (skip) {
      cout << "Basis set not handled - results may be incorrect.\n";
      m_moIndices[i] = indexMO;
      indexMO += skip;
      m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
      skip = 0;
    }
  }
  m_init = true;
}

bool GaussianSet::generateDensity()
{
  if (m_scfType == Unknown)
    return false;

  m_density.resize(m_numMOs, m_numMOs);
  m_density = MatrixX::Zero(m_numMOs, m_numMOs);
  for (unsigned int iBasis = 0; iBasis < m_numMOs; ++iBasis) {
    for (unsigned int jBasis = 0; jBasis <= iBasis; ++jBasis) {
      switch (m_scfType) {
        case Rhf:
          for (unsigned int iMO = 0; iMO < m_electrons[0] / 2; ++iMO) {
            double icoeff = m_moMatrix[0](iBasis, iMO);
            double jcoeff = m_moMatrix[0](jBasis, iMO);
            m_density(jBasis, iBasis) += 2.0 * icoeff * jcoeff;
            m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
          }
          cout << iBasis << ", " << jBasis << ": " << m_density(iBasis, jBasis)
               << endl;
          break;
        case Uhf:
          for (unsigned int iaMO = 0; iaMO < m_electrons[0]; ++iaMO) {
            double icoeff = m_moMatrix[0](iBasis, iaMO);
            double jcoeff = m_moMatrix[0](jBasis, iaMO);
            m_density(jBasis, iBasis) += icoeff * jcoeff;
            m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
          }
          for (unsigned int ibMO = 0; ibMO < m_electrons[1]; ibMO++) {
            double icoeff = m_moMatrix[1](iBasis, ibMO);
            double jcoeff = m_moMatrix[1](jBasis, ibMO);
            m_density(jBasis, iBasis) += icoeff * jcoeff;
            m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
          }
          cout << iBasis << ", " << jBasis << ": " << m_density(iBasis, jBasis)
               << endl;
          break;
        default:
          cout << "Unhandled scf type:" << m_scfType << endl;
      }
    }
  }
  return true;
}

bool GaussianSet::generateSpinDensity()
{
  if (m_scfType != Uhf)
    return false;

  m_spinDensity.resize(m_numMOs, m_numMOs);
  m_spinDensity = MatrixX::Zero(m_numMOs, m_numMOs);
  for (unsigned int iBasis = 0; iBasis < m_numMOs; ++iBasis) {
    for (unsigned int jBasis = 0; jBasis <= iBasis; ++jBasis) {
      for (unsigned int iaMO = 0; iaMO < m_electrons[0]; ++iaMO) {
        double icoeff = m_moMatrix[0](iBasis, iaMO);
        double jcoeff = m_moMatrix[0](jBasis, iaMO);
        m_spinDensity(jBasis, iBasis) += icoeff * jcoeff;
        m_spinDensity(iBasis, jBasis) = m_spinDensity(jBasis, iBasis);
      }
      for (unsigned int ibMO = 0; ibMO < m_electrons[1]; ++ibMO) {
        double icoeff = m_moMatrix[1](iBasis, ibMO);
        double jcoeff = m_moMatrix[1](jBasis, ibMO);
        m_spinDensity(jBasis, iBasis) -= icoeff * jcoeff;
        m_spinDensity(iBasis, jBasis) = m_spinDensity(jBasis, iBasis);
      }
      cout << iBasis << ", " << jBasis << ": " << m_spinDensity(iBasis, jBasis)
           << endl;
    }
  }
  return true;
}

} // End namespace Core
} // End namespace Avogadro
