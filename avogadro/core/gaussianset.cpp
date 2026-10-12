/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussianset.h"

#include "molecule.h"

#include <cmath>
#include <iostream>

using std::cout;
using std::endl;

using std::vector;

namespace Avogadro::Core {

GaussianSet::GaussianSet() : m_numMOs(0), m_init(false), m_scfType(Rhf) {}

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
    case G:
      m_numMOs += 15;
      break;
    case G9:
      m_numMOs += 9;
      break;
    case H:
      m_numMOs += 21;
      break;
    case H11:
      m_numMOs += 11;
      break;
    case I:
      m_numMOs += 28;
      break;
    case I13:
      m_numMOs += 13;
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

unsigned int GaussianSet::molecularOrbitalCount(ElectronType type) const
{
  size_t index(0);
  if (type == Beta)
    index = 1;
  // The number of MOs is the number of columns in the coefficient matrix.
  // The rows are the number of atomic basis functions, which is only equal
  // to the number of MOs for a full canonical set. Reduced/localized sets
  // (IAO/IBO, NBO, Pipek-Mezey, ...) have fewer MOs than basis functions.
  return static_cast<unsigned int>(m_moMatrix[index].cols());
}

void GaussianSet::outputAll(ElectronType type)
{
  size_t index(0);
  if (type == Beta)
    index = 1;

  // Can be called to print out a summary of the basis set as read in
  auto numAtoms = static_cast<unsigned int>(m_molecule->atomCount());
  cout << "\nGaussian Basis Set\nNumber of atoms:" << numAtoms << '\n';
  switch (m_scfType) {
    case Rhf:
      cout << "RHF orbitals" << '\n';
      break;
    case Uhf:
      cout << "UHF orbitals" << '\n';
      break;
    case Rohf:
      cout << "ROHF orbitals" << '\n';
      break;
    default:
      cout << "Unknown orbitals" << '\n';
  }

  initCalculation();

  cout << "Number of electrons = " << m_electrons[index] << '\n';

  if (!isValid()) {
    cout << "Basis set is marked as invalid." << '\n';
    return;
  }

  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    cout << i << "\tAtom Index: " << m_atomIndices[i]
         << "\tSymmetry: " << m_symmetry[i] << "\tMO Index: " << m_moIndices[i]
         << "\tGTO Index: " << m_gtoIndices[i] << '\n';
  }
  cout << "Symmetry: " << m_symmetry.size()
       << "\tgtoIndices: " << m_gtoIndices.size()
       << "\tLast gtoIndex: " << m_gtoIndices[m_symmetry.size()]
       << "\ngto size: " << m_gtoA.size() << " " << m_gtoC.size() << " "
       << m_gtoCN.size() << '\n';
  for (size_t i = 0; i < m_symmetry.size(); ++i) {
    switch (m_symmetry[i]) {
      case S:
        cout << "Shell " << i << "\tS\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](m_moIndices[i], 0) << '\n';
        break;
      case P:
        cout << "Shell " << i << "\tP\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << '\n';
        break;
      case D:
        cout << "Shell " << i << "\tD\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 3) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 4) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 5) << '\n';
        break;
      case D5:
        cout << "Shell " << i << "\tD5\n  MO 1\t"
             << m_moMatrix[index](0, m_moIndices[i]) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 1) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 2) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 3) << "\t"
             << m_moMatrix[index](0, m_moIndices[i] + 4) << '\n';
        break;
      case F:
        cout << "Shell " << i << "\tF\n  MO 1";
        for (short j = 0; j < 10; ++j)
          cout << "\t" << m_moMatrix[index](0, m_moIndices[i] + j);
        cout << '\n';
        break;
      case F7:
        cout << "Shell " << i << "\tF7\n  MO 1";
        for (short j = 0; j < 7; ++j)
          cout << "\t" << m_moMatrix[index](0, m_moIndices[i] + j);
        cout << '\n';
        break;
      default:
        cout << "Error: unhandled type...\n";
    }
    unsigned int cIndex = m_gtoIndices[i];
    for (size_t j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
      if (j >= m_gtoA.size()) {
        cout << "Error, j is too large!" << j << m_gtoA.size() << '\n';
        continue;
      }
      cout << cIndex << "\tc: " << m_gtoC[cIndex] << "\ta: " << m_gtoA[cIndex]
           << '\n';
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

void GaussianSet::swapAtomIndices(Index a, Index b)
{
  const auto first = static_cast<unsigned int>(a);
  const auto second = static_cast<unsigned int>(b);
  for (auto& index : m_atomIndices) {
    if (index == first)
      index = second;
    else if (index == second)
      index = first;
  }
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
          // I think this is correct but really need to check...
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
            // These must follow the component order that pointF() and
            // gridF() evaluate, which is the Gaussian ordering
            //   xxx, yyy, zzz, xyy, xxy, xxz, xzz, yzz, yyz, xyz
            // and NOT the alphabetical ordering the comments here used to
            // claim. They were previously emitted alphabetically, so e.g.
            // slot 1 (yyy) received the xxy constant: five of the ten
            // Cartesian f components came out with the wrong
            // normalization. See GaussianSetToolsTest.shellsAreNormalized.
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // xxx
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // yyy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm1); // zzz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xyy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xxy
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xxz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // xzz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // yzz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm2); // yyz
            m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.25) * norm3); // xyz
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
      case G: {
        // A primitive Cartesian Gaussian x^a y^b z^c exp(-alpha r^2) is
        // normalized by
        //   (2 alpha/pi)^(3/4) (4 alpha)^(l/2)
        //     / sqrt((2a-1)!! (2b-1)!! (2c-1)!!)
        // The base below is (2 alpha/pi)^(3/4) (4 alpha)^2 with the
        // alpha^2.75 factored out into the pow() at each use site; the
        // divisors are the double-factorial products for each l=4 pattern:
        //   (4,0,0) -> 7!! = 105     (3,1,0) -> 5!! 1!! = 15
        //   (2,2,0) -> 3!! 3!! = 9   (2,1,1) -> 3!! = 3
        // The D and F cases above already follow this rule; G did not, and
        // used 1, sqrt(7), sqrt(35/3) and sqrt(35) instead. See
        // GaussianSetToolsTest.shellsAreNormalized.
        // 16 * (2.0/pi)^0.75
        double norm = 11.403287525679843;
        double norm0 = norm / sqrt(105.0); // xxxx, yyyy, zzzz
        double norm1 = norm / sqrt(15.0);  // xxxy and friends
        double norm2 = norm / 3.0;         // xxyy and friends
        double norm3 = norm / sqrt(3.0);   // xxyz and friends
        m_moIndices[i] = indexMO;
        indexMO += 15;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          // molden order
          // xxxx yyyy zzzz xxxy xxxz yyyx yyyz zzzx zzzy,
          // xxyy xxzz yyzz xxyz yyxz zzxy
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm0); // xxxx
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm0); // yyyy
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm0); // zzzz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // xxxy
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // xxxz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // yyyx
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // yyyz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // zzzx
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm1); // zzzy
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm2); // xxyy
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm2); // xxzz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm2); // yyzz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm3); // xxyz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm3); // yyxz
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * norm3); // zzxy
        }
      } break;
      case G9: {
        // The nine real solid harmonics used by pointG9/gridG9 are not
        // uniformly scaled relative to each other, so a single
        // m-independent constant cannot normalize them all: m = 0, +-2 and
        // +-4 need sqrt(105), m = +-1 needs sqrt(105/8) and m = +-3 needs
        // sqrt(21/2). Using one constant for all nine (as this did) leaves
        // the *relative* weights within a g shell wrong, not merely the
        // overall scale. See GaussianSetToolsTest.shellsAreNormalized.
        // 16 * (2.0/pi)^0.75
        double norm = 11.403287525679843;
        double normA = norm / sqrt(105.0);       // m = 0, +-2, +-4
        double normB = norm / sqrt(105.0 / 8.0); // m = +-1
        double normC = norm / sqrt(21.0 / 2.0);  // m = +-3
        m_moIndices[i] = indexMO;
        indexMO += 9;
        m_cIndices.push_back(static_cast<unsigned int>(m_gtoCN.size()));
        for (unsigned j = m_gtoIndices[i]; j < m_gtoIndices[i + 1]; ++j) {
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normA); // 0
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normB); //+1
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normB); //-1
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normA); //+2
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normA); //-2
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normC); //+3
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normC); //-3
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normA); //+4
          m_gtoCN.push_back(m_gtoC[j] * pow(m_gtoA[j], 2.75) * normA); //-4
        }
      } break;
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

bool GaussianSet::generateDensityMatrix()
{
  if (m_scfType == Unknown)
    return false;

  if (m_moMatrix[0].size() == 0)
    return false;
  // check if it's Rohf or Uhf too
  if (m_scfType != Rhf && m_moMatrix[1].size() == 0)
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
          //          cout << iBasis << ", " << jBasis << ": " <<
          //          m_density(iBasis, jBasis)
          //               << endl;
          break;
        case Rohf: // ROHF is handled similarly to UHF
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
          //          cout << iBasis << ", " << jBasis << ": " <<
          //          m_density(iBasis, jBasis)
          //               << endl;
          break;
        default:
          cout << "Unhandled scf type:" << m_scfType << '\n';
      }
    }
  }
  return true;
}

bool GaussianSet::generateSpinDensityMatrix()
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
           << '\n';
    }
  }
  return true;
}

} // namespace Avogadro::Core
