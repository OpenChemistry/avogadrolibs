/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "molecule.h"

namespace Avogadro {
namespace QtGui {

Molecule::Molecule(QObject *parent_) : QObject(parent_)
{
}

Molecule::Molecule(const Molecule &other)
  : QObject(), Core::Molecule(other)
{
  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule& Molecule::operator=(const Molecule& other)
{
  // Call the base classes assigment operator
  Core::Molecule::operator= (other);

  // Copy over the unique ids
  m_atomUniqueIds = other.m_atomUniqueIds;
  m_bondUniqueIds = other.m_bondUniqueIds;

  return *this;
}


Molecule& Molecule::operator=(const Core::Molecule& other)
{
  // Call the base classes assigment operator
  Core::Molecule::operator= (other);

  // Reset the unique ids.
  m_atomUniqueIds.clear();
  for (Index i = 0; i < atomCount(); ++i)
    m_atomUniqueIds.push_back(i);

  m_bondUniqueIds.clear();
  for (Index i = 0; i < bondCount(); ++i)
    m_bondUniqueIds.push_back(i);

  return *this;
}

Molecule::~Molecule()
{
}

Core::Atom Molecule::addAtom(unsigned char atomicNumber)
{
  m_atomUniqueIds.push_back(atomCount());
  Core::Atom a = Core::Molecule::addAtom(atomicNumber);
  return a;
}

Core::Atom Molecule::addAtom(unsigned char atomicNumber, Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size())
      || m_atomUniqueIds[uniqueId] != MaxIndex) {
    return Core::Atom();
  }

  m_atomUniqueIds[uniqueId] = atomCount();
  Core::Atom a = Core::Molecule::addAtom(atomicNumber);
  return a;
}

bool Molecule::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;
  Index uniqueId = findAtomUniqueId(index);
  if (uniqueId == MaxIndex)
    return false;

  // Unique ID of an atom that was removed:
  m_atomUniqueIds[uniqueId] = MaxIndex;

  // Before removing the atom we must first remove any bonds to it.
  std::vector<Core::Bond> atomBonds = Core::Molecule::bonds(atom(index));
  while (atomBonds.size()) {
    removeBond(atomBonds.back());
    atomBonds = Core::Molecule::bonds(atom(index));
  }

  Index newSize = static_cast<Index>(m_atomicNumbers.size() - 1);
  if (index != newSize) {
    // We need to move the last atom to this position, and update its unique ID.
    m_atomicNumbers[index] = m_atomicNumbers.back();
    if (m_positions2d.size() == m_atomicNumbers.size())
      m_positions2d[index] = m_positions2d.back();
    if (m_positions3d.size() == m_atomicNumbers.size())
      m_positions3d[index] = m_positions3d.back();

    // Find any bonds to the moved atom and update their index.
    atomBonds = Core::Molecule::bonds(atom(newSize));
    foreach (const Core::Bond &currentBond, atomBonds) {
      std::pair<Index, Index> bondPair = m_bondPairs[currentBond.index()];
      if (bondPair.first == newSize)
        bondPair.first = index;
      else if (bondPair.second == newSize)
        bondPair.second = index;
      m_bondPairs[currentBond.index()] = bondPair;
    }

    Index movedAtomUID = findAtomUniqueId(newSize);
    assert(movedAtomUID != MaxIndex);
    m_atomUniqueIds[movedAtomUID] = index;
  }
  // Resize the arrays for the smaller molecule.
  if (m_positions2d.size() == m_atomicNumbers.size())
    m_positions2d.resize(newSize);
  if (m_positions3d.size() == m_atomicNumbers.size())
    m_positions3d.resize(newSize);
  m_atomicNumbers.resize(newSize);

  return true;
}

bool Molecule::removeAtom(const Core::Atom &atom_)
{
  return removeAtom(atom_.index());
}

Core::Atom Molecule::atomByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size())
      || m_atomUniqueIds[uniqueId] == MaxIndex) {
    return Core::Atom();
  }
  else {
    return Core::Atom(this, m_atomUniqueIds[uniqueId]);
  }
}

Index Molecule::atomUniqueId(const Core::Atom &a) const
{
  if (a.molecule() != this)
    return MaxIndex;
  return findAtomUniqueId(a.index());
}

Core::Bond Molecule::addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder)
{
  m_bondUniqueIds.push_back(bondCount());
  Core::Bond bond_ = Core::Molecule::addBond(a, b, bondOrder);
  return bond_;
}

Core::Bond Molecule::addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder, Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size())
      || m_bondUniqueIds[uniqueId] != MaxIndex) {
    return Core::Bond();
  }

  m_bondUniqueIds[uniqueId] = bondCount();
  Core::Bond bond_ = Core::Molecule::addBond(a, b, bondOrder);
  return bond_;
}

bool Molecule::removeBond(Index index)
{
  if (index >= bondCount())
    return false;
  Index uniqueId = findBondUniqueId(index);
  if (uniqueId == MaxIndex)
    return false;

  m_bondUniqueIds[uniqueId] = MaxIndex; // Unique ID of a bond that was removed.

  Index newSize = static_cast<Index>(m_bondOrders.size() - 1);
  if (index != newSize) {
    // We need to move the last bond to this position, and update its unique ID.
    m_bondOrders[index] = m_bondOrders.back();
    m_bondPairs[index] = m_bondPairs.back();

    Index movedBondUID = findBondUniqueId(newSize);
    assert(movedBondUID != MaxIndex);
    m_bondUniqueIds[movedBondUID] = index;
  }

  // Resize the arrays for the smaller molecule.
  m_bondOrders.resize(newSize);
  m_bondPairs.resize(newSize);

  return true;
}

bool Molecule::removeBond(const Core::Bond &bond_)
{
  return removeBond(bond_.index());
}

bool Molecule::removeBond(const Core::Atom &a, const Core::Atom &b)
{
  return removeBond(bond(a, b).index());
}

Core::Bond Molecule::bondByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size())
      || m_bondUniqueIds[uniqueId] == MaxIndex) {
    return Core::Bond();
  }
  else {
    return Core::Bond(this, static_cast<Index>(m_bondUniqueIds[uniqueId]));
  }
}

Index Molecule::bondUniqueId(const Core::Bond &b) const
{
  if (b.molecule() != this)
    return MaxIndex;
  return findBondUniqueId(b.index());
}

void Molecule::emitChanged(unsigned int change)
{
  if (change != NoChange)
    emit changed(change);
}

inline Index Molecule::findAtomUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_atomUniqueIds.size()); ++i)
    if (m_atomUniqueIds[i] == index)
      return i;
  return MaxIndex;
}

inline Index Molecule::findBondUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_bondUniqueIds.size()); ++i)
    if (m_bondUniqueIds[i] == index)
      return i;
  return MaxIndex;
}

} // end QtGui namespace
} // end Avogadro namespace
