/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "residue.h"
#include "molecule.h"
#include "residuedata.h"

namespace Avogadro {
namespace Core {

Residue::Residue() {}

Residue::Residue(std::string& name) : m_residueName(name), m_heterogen(false) {}

Residue::Residue(std::string& name, Index& number)
  : m_residueName(name), m_residueId(number), m_heterogen(false)
{}

Residue::Residue(std::string& name, Index& number, char& id)
  : m_residueName(name), m_residueId(number), m_chainId(id), m_heterogen(false)
{}

Residue::Residue(const Residue& other)
  : m_residueName(other.m_residueName), m_residueId(other.m_residueId),
    m_atomNameMap(other.m_atomNameMap), m_heterogen(other.m_heterogen)
{}

Residue& Residue::operator=(Residue other)
{
  m_residueName = other.m_residueName;
  m_residueId = other.m_residueId;
  m_atomNameMap = other.m_atomNameMap;
  m_heterogen = other.m_heterogen;
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

Atom Residue::getAtomByName(std::string name)
{
  Atom empty;
  auto search = m_atomNameMap.find(name);
  if (search != m_atomNameMap.end()) {
    return search->second;
  }

  return empty;
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

int Residue::getAtomicNumber(std::string name)
{
  auto search = m_atomNameMap.find(name);
  if (search != m_atomNameMap.end()) {
    return search->second.atomicNumber();
  }

  return 0;
}

} // namespace Core
} // namespace Avogadro
