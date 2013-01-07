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

#include "molden.h"

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

MoldenFile::MoldenFile(const QString &filename, GaussianSet* basis):
  m_coordFactor(1.0), m_currentMode(NotParsing)
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

MoldenFile::~MoldenFile()
{
}

void MoldenFile::processLine()
{
  // First truncate the line, remove trailing white space and check for blank lines
  QString key = m_in->readLine().trimmed();
  while(key.isEmpty() && !m_in->atEnd()) {
    key = m_in->readLine().trimmed();
  }

  if (m_in->atEnd())
    return;

  QStringList list = key.split(' ', QString::SkipEmptyParts);

  // Big switch statement checking for various things we are interested in
  // Make sure to switch mode:
  //      enum mode { NotParsing, Atoms, GTO, STO, MO, SCF }
  if (key.contains("[atoms]", Qt::CaseInsensitive)) {
    if (list.size() > 1 && list[1].contains("au", Qt::CaseInsensitive))
      m_coordFactor = BOHR_TO_ANGSTROM;
    m_currentMode = Atoms;
  } else if (key.contains("[gto]", Qt::CaseInsensitive)) {
    m_currentMode = GTO;
  } else if (key.contains("[mo]", Qt::CaseInsensitive)) {
    m_currentMode = MO;
  } else if (key.contains("[")) { // unknown section
    m_currentMode = NotParsing;
  } else {
    QString shell;
    orbital shellType;

    // parsing a line -- what mode are we in?
    switch (m_currentMode) {
    case Atoms:
      // element_name number atomic_number x y z
      if (list.size() < 6)
        return;
      m_aNums.push_back(list[2].toInt());
      m_aPos.push_back(list[3].toDouble() * m_coordFactor);
      m_aPos.push_back(list[4].toDouble() * m_coordFactor);
      m_aPos.push_back(list[5].toDouble() * m_coordFactor);

      break;
    case GTO:
    {
      // TODO: detect dead files and make bullet-proof
      int atom = list[0].toInt();

      key = m_in->readLine().trimmed();
      while (!key.isEmpty()) { // read the shell types in this GTO
        list = key.split(' ', QString::SkipEmptyParts);
        shell = list[0].toLower();
        shellType = Quantum::UU;
        if (shell.contains("sp"))
          shellType = Quantum::SP;
        else if (shell.contains("s"))
          shellType = Quantum::S;
        else if (shell.contains("p"))
          shellType = Quantum::P;
        else if (shell.contains("d"))
          shellType = Quantum::D;
        else if (shell.contains("f"))
          shellType = Quantum::F;

        if (shellType != Quantum::UU) {
          m_shellTypes.push_back(shellType);
          m_shelltoAtom.push_back(atom);
        }
        else
          return;

        int numGTOs = list[1].toInt();
        m_shellNums.push_back(numGTOs);

        // now read all the exponents and contraction coefficients
        for (int gto = 0; gto < numGTOs; ++gto) {
          key = m_in->readLine().trimmed();
          list = key.split(' ', QString::SkipEmptyParts);
          m_a.push_back(list[0].toDouble());
          m_c.push_back(list[1].toDouble());
          if (shellType == Quantum::SP && list.size() > 2)
            m_csp.push_back(list[2].toDouble());
        } // finished parsing a new GTO
        key = m_in->readLine().trimmed(); // start reading the next shell
      }
    }
    break;

    case MO:
      // parse occ, spin, energy, etc.
      while (!key.isEmpty() && key.contains('=')) {
        key = m_in->readLine().trimmed();
        list = key.split(' ', QString::SkipEmptyParts);
        if (key.contains("occup", Qt::CaseInsensitive))
          m_electrons += (int)list[1].toDouble();
      }

      // parse MO coefficients
      while (!key.isEmpty() && !key.contains('=')) {
        list = key.split(' ', QString::SkipEmptyParts);
        if (list.size() < 2)
          break;

        m_MOcoeffs.push_back(list[1].toDouble());
        key = m_in->readLine().trimmed();
      } // finished parsing a new MO

      break;
    default:
      break;
    }
  }
}

void MoldenFile::load(GaussianSet* basis)
{
  // Now load up our basis set
  basis->setNumElectrons(m_electrons);
  int nAtom = 0;
  for (unsigned int i = 0; i < m_aPos.size(); i += 3)
    basis->addAtom(Vector3d(m_aPos.at(i), m_aPos.at(i+1), m_aPos.at(i+2)),
                   m_aNums.at(nAtom++));

  // Set up the GTO primitive counter, go through the shells and add them
  int nGTO = 0;
  int nSP = 0; // number of SP shells
  for (unsigned int i = 0; i < m_shellTypes.size(); ++i) {

    // Handle the SP case separately - this should possibly be a distinct type
    if (m_shellTypes.at(i) == SP)  {
      // SP orbital type - currently have to unroll into two shells
      int s = basis->addBasis(m_shelltoAtom.at(i) - 1, S);
      int p = basis->addBasis(m_shelltoAtom.at(i) - 1, P);
      for (int j = 0; j < m_shellNums.at(i); ++j) {
        basis->addGTO(s, m_c.at(nGTO), m_a.at(nGTO));
        basis->addGTO(p, m_csp.at(nSP), m_a.at(nGTO));
        ++nSP;
        ++nGTO;
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
  // Now to load in the MO coefficients
  if (m_MOcoeffs.size())
    basis->addMOs(m_MOcoeffs);
}

void MoldenFile::outputAll()
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
