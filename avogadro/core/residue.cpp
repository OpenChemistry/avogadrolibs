/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "residue.h"
#include "molecule.h"
#include "residuecolors.h"
#include "residuedata.h"

namespace Avogadro {
namespace Core {

Residue::Residue() {}

Residue::Residue(std::string& name)
  : m_residueName(name), m_chainId('A'), m_heterogen(false), m_color(0,0,0), m_customColorSet(false)
{}

Residue::Residue(std::string& name, Index& number)
  : m_residueName(name), m_residueId(number), m_chainId('A'), m_heterogen(false), m_color(0,0,0), m_customColorSet(false)
{}

Residue::Residue(std::string& name, Index& number, char& id)
  : m_residueName(name), m_residueId(number), m_chainId(id), m_heterogen(false), m_color(0,0,0), m_customColorSet(false)
{}

Residue::Residue(const Residue& other)
  : m_residueName(other.m_residueName), m_residueId(other.m_residueId),
    m_chainId(other.m_chainId), m_atomNameMap(other.m_atomNameMap),
    m_heterogen(other.m_heterogen), m_color(other.m_color), m_customColorSet(other.m_customColorSet)
{}

Residue& Residue::operator=(Residue other)
{
  m_residueName = other.m_residueName;
  m_residueId = other.m_residueId;
  m_chainId = other.m_chainId;
  m_atomNameMap = other.m_atomNameMap;
  m_heterogen = other.m_heterogen;
  m_color = other.m_color;
  m_customColorSet = other.m_customColorSet;
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

void Residue::setColor(const Vector3ub color)
{
  m_customColorSet = true;
  m_color = color;
}

const Vector3ub Residue::color() const
{
  if (m_customColorSet)
  return m_color;

  // default return a color for the chain
  int offset = 0;
  if (m_chainId >= 'A' && m_chainId <= 'Z')
     offset = m_chainId - 'A';
  else if (m_chainId >= 'a' && m_chainId <= 'z')
     offset = m_chainId - 'a';
  else if (m_chainId >= '0' && m_chainId <= '9')
     offset = m_chainId - '0' + 15;// starts at 'P'

  return Vector3ub(chain_color[offset]);
}

} // namespace Core
} // namespace Avogadro
