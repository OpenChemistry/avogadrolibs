/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "residue.h"
#include "molecule.h"
#include "residuedata.h"

namespace Avogadro {
namespace Core {

Residue::Residue() {}

Residue::Residue(std::string& name)
  : m_residueName(name)
{}

Residue::Residue(std::string& name, Index& number)
  : m_residueName(name)
  , m_residueId(number)
{}

Residue::Residue(std::string& name, Index& number, char& id)
  : m_residueName(name)
  , m_residueId(number)
  , m_chainId(id)
{}

Residue::Residue(const Residue& other)
  : m_residueName(other.m_residueName)
  , m_residueId(other.m_residueId)
  , m_atomNameMap(other.m_atomNameMap)
{}

Residue& Residue::operator=(Residue other)
{
  m_residueName = other.m_residueName;
  m_residueId = other.m_residueId;
  m_atomNameMap = other.m_atomNameMap;
  return *this;
}

Residue::~Residue() {}

void Residue::addResidueAtom(std::string& name, Atom& atom)
{
  m_atomNameMap.insert(std::pair<std::string, Atom>(name, atom));
}

std::vector<Atom> Residue::residueAtoms()
{
  std::vector<Atom> res;
  for (AtomNameMap::iterator it = m_atomNameMap.begin();
       it != m_atomNameMap.end(); ++it) {
    res.push_back(it->second);
  }
  return res;
}

void Residue::resolveResidueBonds(Molecule& mol)
{
  std::vector<std::pair<std::string, std::string>> bondSeq;
  if (residueDict.find(m_residueName) != residueDict.end()) {
    size_t i = 0;
    bondSeq = residueDict[m_residueName].residueSingleBonds();
    for (i = 0; i < bondSeq.size(); ++i) {
      if (m_atomNameMap.find(bondSeq[i].first) != m_atomNameMap.end() &&
          m_atomNameMap.find(bondSeq[i].second) != m_atomNameMap.end()) {
        mol.Avogadro::Core::Molecule::addBond(
          m_atomNameMap[bondSeq[i].first], m_atomNameMap[bondSeq[i].second], 1);
      }
    }
    bondSeq = residueDict[m_residueName].residueDoubleBonds();
    for (i = 0; i < bondSeq.size(); ++i) {
      if (m_atomNameMap.find(bondSeq[i].first) != m_atomNameMap.end() &&
          m_atomNameMap.find(bondSeq[i].second) != m_atomNameMap.end()) {
        mol.Avogadro::Core::Molecule::addBond(
          m_atomNameMap[bondSeq[i].first], m_atomNameMap[bondSeq[i].second], 2);
      }
    }
  }
}

} // end Core namespace
} // end Avogadro namespace
