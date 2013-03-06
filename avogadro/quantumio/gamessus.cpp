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

#include <QtCore/QFile>
#include <QtCore/QStringList>
#include <QtCore/QDebug>

using Eigen::Vector3d;
using std::vector;

#ifndef BOHR_TO_ANGSTROM
#define BOHR_TO_ANGSTROM 0.529177249
#endif

namespace Avogadro {
namespace QuantumIO {

using Quantum::S;
using Quantum::SP;
using Quantum::P;
using Quantum::D;
using Quantum::F;
using Quantum::UU;

using Quantum::orbital;

GAMESSUSOutput::GAMESSUSOutput(const QString &filename, GaussianSet* basis) :
  m_coordFactor(1.0), m_currentMode(NotParsing), m_currentScfMode(doubly),
  m_currentAtom(1)
{
  // Open the file for reading and process it
  QFile* file = new QFile(filename);
  file->open(QIODevice::ReadOnly | QIODevice::Text);
  m_in = file;

  qDebug() << "File" << filename << "opened.";

  // Process the formatted checkpoint and extract all the information we need
  while (!m_in->atEnd())
    processLine(basis);

  // Now it should all be loaded load it into the basis set
  load(basis);

  delete file;
}

GAMESSUSOutput::~GAMESSUSOutput()
{
}

void GAMESSUSOutput::processLine(GaussianSet *basis)
{
  // First truncate the line, remove trailing white space and check for blank lines
  QString key = m_in->readLine().trimmed();
  while (key.isEmpty() && !m_in->atEnd())
    key = m_in->readLine().trimmed();

  if (m_in->atEnd())
    return;

  QStringList list2;
  QString     tmp;
  QStringList list = key.split(' ', QString::SkipEmptyParts);
  int numGTOs;

  // Big switch statement checking for various things we are interested in
  // Make sure to switch mode:
  //      enum mode { NotParsing, Atoms, GTO, STO, MO, SCF }
  if (key.contains("COORDINATES (BOHR)", Qt::CaseInsensitive)) {
    // FIXME: Add back clear if necessary.
    // basis->moleculeRef().clear();

    m_coordFactor = 1.0; // coordinates are supposed to be in bohr?!
    m_currentMode = Atoms;
    key = m_in->readLine().trimmed(); // skip the column titles
  } else if (key.contains("COORDINATES OF ALL ATOMS ARE (ANGS)",
                          Qt::CaseInsensitive)) {
    // FIXME: Add back clear if necessary.
    // basis->moleculeRef().clearAtoms();

    m_coordFactor = 1.0 / BOHR_TO_ANGSTROM; // in Angstroms now
    m_currentMode = Atoms;
    key = m_in->readLine(); // skip column titles
    key = m_in->readLine(); // and ----- line
  } else if (key.contains("INTERNUCLEAR DISTANCES", Qt::CaseInsensitive)) {
    //this silly parser is far too greedy
    m_currentMode = NotParsing;
  } else if (key.contains("ATOMIC BASIS SET")) {
    m_currentMode = GTO;
    // ---
    // PRIMITIVE
    // BASIS FUNC
    // blank
    // column header
    // blank
    // element
    for (unsigned int i = 0; i < 7; ++i) {
      key = m_in->readLine();
    }
  } else if (key.contains("TOTAL NUMBER OF BASIS SET")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (key.contains("NUMBER OF CARTESIAN GAUSSIAN BASIS")) {
    m_currentMode = NotParsing; // no longer reading GTOs
  } else if (key.contains("NUMBER OF ELECTRONS")) {
    m_electrons = list[4].toInt();
  } else if (key.contains("NUMBER OF OCCUPIED ORBITALS (ALPHA)")) {
    m_electronsA = list[6].toInt();
  } else if (key.contains("NUMBER OF OCCUPIED ORBITALS (BETA )")) {
    m_electronsB = list[7].toInt();
  } else if (key.contains("SCFTYP=")) {
    //the SCFtyp is necessary to know what we are reading
      list = key.split(' ');
      tmp = list[0];
      list2 = tmp.split('=');
      tmp = list2[1];
      if (tmp.contains("RHF"))
        m_scftype=rhf;
      else if (tmp.contains("UHF"))
        m_scftype=uhf;
      else if (tmp.contains("ROHF"))
        m_scftype=rohf;
      else {
        qDebug() << "SCF type = " << tmp << " cannot be read.";
        m_scftype=Unknown;
        return;
      }
  } else if (key.contains("----- ALPHA SET -----") && m_scftype==uhf) {
    m_currentMode = MO;
    m_currentScfMode = alpha;
    key = m_in->readLine(); // blank line
    key = m_in->readLine(); // ------------
    key = m_in->readLine(); // EIGENVECTORS
    key = m_in->readLine(); // ------------
    key = m_in->readLine(); // blank line
  } else if (key.contains("EIGENVECTORS") && m_currentScfMode==beta) {
    //beta is set at the conclustion of alpha reads
    m_currentMode = MO;
    key = m_in->readLine(); // ------------
    key = m_in->readLine(); // blank line
  } else if (key.contains("EIGENVECTORS") && m_scftype==rhf) {
    //|| key.contains("MOLECULAR ORBITALS")) {
    m_currentMode = MO;
    m_currentScfMode = doubly;
    key = m_in->readLine(); // ----
    key = m_in->readLine(); // blank line
  } else {
    QString shell;
    orbital shellType;
    vector <vector <double> > columns;
    unsigned int numColumns, numRows;

    // parsing a line -- what mode are we in?
    switch (m_currentMode) {
    case Atoms: {
      // element_name atomic_number x y z
      if (list.size() < 5)
        return;
      Vector3d pos(list[2].toDouble() * m_coordFactor,
                   list[3].toDouble() * m_coordFactor,
                   list[4].toDouble() * m_coordFactor);
      basis->addAtom(pos, int(list[1].toDouble()));
      break;
    }
    case GTO:
      // should start at the first line of shell functions
      if (key.isEmpty())
        break;
      list = key.split(' ', QString::SkipEmptyParts);
      numGTOs = 0;
      while (list.size() > 1) {
        numGTOs++;
        shell = list[1].toLower();
        shellType = UU;
        if (shell.contains("s"))
          shellType = S;
        else if (shell.contains("l"))
          shellType = SP;
        else if (shell.contains("p"))
          shellType = P;
        else if (shell.contains("d"))
          shellType = D;
        else if (shell.contains("f"))
          shellType = F;
        else
          return;

        m_a.push_back(list[3].toDouble());
        m_c.push_back(list[4].toDouble());
        if (shellType == SP && list.size() > 4)
          m_csp.push_back(list[5].toDouble());

        // read to the next shell
        key = m_in->readLine().trimmed();
        if (key.isEmpty()) {
          key = m_in->readLine().trimmed();
          m_shellNums.push_back(numGTOs);
          m_shellTypes.push_back(shellType);
          m_shelltoAtom.push_back(m_currentAtom);
          numGTOs = 0;
        }
        list = key.split(' ', QString::SkipEmptyParts);
      } // end "while list > 1) -- i.e., we're on the next atom line

      key = m_in->readLine(); // start reading the next atom
      m_currentAtom++;
      break;

    case MO:
      switch (m_currentScfMode) {
      case alpha:
        m_alphaMOcoeffs.clear();
        break;
      case beta:
        m_betaMOcoeffs.clear();
        break;
      case doubly:
        m_MOcoeffs.clear(); // if the orbitals were punched multiple times
        break;
      default:
        ;
      }
      while (!key.contains("END OF") && !key.contains("-----")) {
        // currently reading the MO number
        key = m_in->readLine(); // energies
        key = m_in->readLine(); // symmetries
        key = m_in->readLine(); // now we've got coefficients
        list = key.split(' ', QString::SkipEmptyParts);
        while (list.size() > 5) {
          numColumns = list.size() - 4;
          columns.resize(numColumns);
          for (unsigned int i = 0; i < numColumns; ++i)
            columns[i].push_back(list[i + 4].toDouble());

          key = m_in->readLine();
          if (key.contains(QLatin1String("END OF RHF")) ||
              key.contains(QLatin1String("END OF UHF"))) {
            break;
          }
          list = key.split(' ', QString::SkipEmptyParts);
        } // ok, we've finished one batch of MO coeffs

        // Now we need to re-order the MO coeffs, so we insert one MO at a time
        for (unsigned int i = 0; i < numColumns; ++i) {
          numRows = static_cast<unsigned int>(columns[i].size());
          for (unsigned int j = 0; j < numRows; ++j) {
            //qDebug() << "push back" << columns[i][j];
            switch (m_currentScfMode) {
            case alpha:
              m_alphaMOcoeffs.push_back(columns[i][j]);
              break;
            case beta:
              m_betaMOcoeffs.push_back(columns[i][j]);
              break;
            case doubly:
              m_MOcoeffs.push_back(columns[i][j]);
              break;
            default:
              ;
            }
          }
        }
        columns.clear();

        if (key.trimmed().isEmpty())
          key = m_in->readLine(); // skip the blank line after the MOs
      } // finished parsing MOs
      m_currentMode = NotParsing;
      if (m_currentScfMode == alpha)
        m_currentScfMode = beta;
      break;

    default:
      ;
    } // end switch
  } // end if (mode)
} // end process line

void GAMESSUSOutput::load(GaussianSet* basis)
{
  outputAll();

  // Now load up our basis set
  basis->setNumElectrons(m_electrons);
  basis->setNumAlphaElectrons(m_electronsA);
  basis->setNumBetaElectrons(m_electronsB);

  //    qDebug() << m_shellTypes.size() << m_shellNums.size() << m_shelltoAtom.size() << m_a.size() << m_c.size() << m_csp.size();

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  int nSP = 0; // number of SP shells
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes.at(i) == SP)  {
      // SP orbital type - currently have to unroll into two shells
      int tmpGTO = nGTO;
      int s = basis->addBasis(m_shelltoAtom.at(i) - 1, S);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(s, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
      int p = basis->addBasis(m_shelltoAtom.at(i) - 1, P);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(p, m_csp.at(nSP), m_a.at(tmpGTO));
        ++tmpGTO;
        ++nSP;
      }
    }
    else {
      int b = basis->addBasis(m_shelltoAtom.at(i) - 1, m_shellTypes.at(i));
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(b, m_c.at(nGTO), m_a.at(nGTO));
        ++nGTO;
      }
    }
  }
  //    qDebug() << " loading MOs " << m_MOcoeffs.size();

  // Now to load in the MO coefficients
  if (m_MOcoeffs.size())
    basis->addMOs(m_MOcoeffs);
  if (m_alphaMOcoeffs.size())
    basis->addAlphaMOs(m_alphaMOcoeffs);
  if (m_betaMOcoeffs.size())
    basis->addBetaMOs(m_betaMOcoeffs);

  //generateDensity();
  //if (m_density.rows())
    //basis->setDensityMatrix(m_density);

  switch (m_scftype) {
  case rhf:
    basis->m_scfType = Quantum::rhf;
    break;
  case uhf:
    basis->m_scfType = Quantum::uhf;
    break;
  case rohf:
    basis->m_scfType = Quantum::rohf;
    break;
  case Unknown:
    basis->m_scfType = Quantum::Unknown;
    break;
  default:
    basis->m_scfType = Quantum::Unknown;
    break;
  }
  qDebug() << " done loadBasis ";
}

void GAMESSUSOutput::outputAll()
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
    qDebug() << "SCF typ = Unknown";
  }
  qDebug() << "Shell mappings.";
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {
    qDebug() << i << ": type =" << m_shellTypes.at(i)
             << ", number =" << m_shellNums.at(i)
             << ", atom =" << m_shelltoAtom.at(i);
  }
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

void GAMESSUSOutput::generateDensity()
{
  m_numBasisFunctions = static_cast<unsigned int>(
        sqrt(static_cast<double>(m_MOcoeffs.size())));
  m_density.resize(m_numBasisFunctions, m_numBasisFunctions);
  m_density=Eigen::MatrixXd::Zero(m_numBasisFunctions,m_numBasisFunctions);
  unsigned int electronPairs = static_cast<unsigned int>(m_electrons / 2);
  for (unsigned int iBasis = 0; iBasis < m_numBasisFunctions; ++iBasis) {
    for (unsigned int jBasis = 0; jBasis <= iBasis; ++jBasis) {
      for (unsigned int iMO = 0; iMO < electronPairs; ++iMO) {
        double icoeff = m_MOcoeffs.at(iMO * m_numBasisFunctions + iBasis);
        double jcoeff = m_MOcoeffs.at(iMO * m_numBasisFunctions + jBasis);
        m_density(jBasis, iBasis) += 2.0 * icoeff * jcoeff;
        m_density(iBasis, jBasis) = m_density(jBasis, iBasis);
      }
      qDebug() << iBasis << ", " << jBasis << ": " << m_density(iBasis, jBasis);
    }
  }
}

}
}
