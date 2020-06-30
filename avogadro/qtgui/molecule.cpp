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
#include "rwmolecule.h"

namespace Avogadro {
namespace QtGui {

Molecule::Molecule(QObject* parent_)
  : QObject(parent_), m_undoMolecule(new RWMolecule(*this, this)), constraints()
{
  m_undoMolecule->setInteractive(true);
}

Molecule::Molecule(const Molecule& other)
  : QObject(), Core::Molecule(other),
    m_undoMolecule(new RWMolecule(*this, this)), constraints()
{
  m_undoMolecule->setInteractive(true);
  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule::Molecule(const Core::Molecule& other)
  : QObject(), Core::Molecule(other), constraints()
{
  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule& Molecule::operator=(const Molecule& other)
{
  // Call the base classes assignment operator
  Core::Molecule::operator=(other);

  // Copy over the unique ids
  m_atomUniqueIds = other.m_atomUniqueIds;
  m_bondUniqueIds = other.m_bondUniqueIds;

  return *this;
}

Molecule& Molecule::operator=(const Core::Molecule& other)
{
  // Call the base classes assignment operator
  Core::Molecule::operator=(other);

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

Molecule::AtomType Molecule::addAtom(unsigned char number)
{
  m_atomUniqueIds.push_back(atomCount());
  AtomType a = Core::Molecule::addAtom(number);
  return a;
}

Molecule::AtomType Molecule::addAtom(unsigned char number, Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size()) ||
      m_atomUniqueIds[uniqueId] != MaxIndex) {
    return AtomType();
  }

  m_atomUniqueIds[uniqueId] = atomCount();
  AtomType a = Core::Molecule::addAtom(number);
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
  Core::Array<BondType> atomBonds = Core::Molecule::bonds(atom(index));
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
    foreach (const BondType& currentBond, atomBonds) {
      std::pair<Index, Index> pair = m_bondPairs[currentBond.index()];
      if (pair.first == newSize)
        pair.first = index;
      else if (pair.second == newSize)
        pair.second = index;
      m_bondPairs[currentBond.index()] = pair;
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

bool Molecule::removeAtom(const AtomType& atom_)
{
  return removeAtom(atom_.index());
}

Molecule::AtomType Molecule::atomByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size()) ||
      m_atomUniqueIds[uniqueId] == MaxIndex) {
    return AtomType();
  } else {
    return AtomType(this, m_atomUniqueIds[uniqueId]);
  }
}

Index Molecule::atomUniqueId(const AtomType& a) const
{
  if (a.molecule() != this)
    return MaxIndex;
  return findAtomUniqueId(a.index());
}

Index Molecule::atomUniqueId(Index a) const
{
  return findAtomUniqueId(a);
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order)
{
  m_bondUniqueIds.push_back(bondCount());
  assert(a.isValid() && a.molecule() == this);
  assert(b.isValid() && b.molecule() == this);

  BondType bond_ = Core::Molecule::addBond(a.index(), b.index(), order);
  return bond_;
}

Molecule::BondType Molecule::addBond(Avogadro::Index atomId1,
                                     Avogadro::Index atomId2,
                                     unsigned char order)
{
  m_bondUniqueIds.push_back(bondCount());
  return Core::Molecule::addBond(atomId1, atomId2, order);
}

Molecule::BondType Molecule::addBond(const AtomType& a, const AtomType& b,
                                     unsigned char order, Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size()) ||
      m_bondUniqueIds[uniqueId] != MaxIndex) {
    return BondType();
  }

  m_bondUniqueIds[uniqueId] = bondCount();
  return Core::Molecule::addBond(a, b, order);
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

bool Molecule::removeBond(const BondType& bond_)
{
  return removeBond(bond_.index());
}

bool Molecule::removeBond(const AtomType& a, const AtomType& b)
{
  return removeBond(bond(a, b).index());
}

bool Molecule::removeBond(Index a, Index b)
{
  return removeBond(bond(a, b).index());
}

Molecule::BondType Molecule::bondByUniqueId(Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size()) ||
      m_bondUniqueIds[uniqueId] == MaxIndex) {
    return BondType();
  } else {
    return BondType(this, static_cast<Index>(m_bondUniqueIds[uniqueId]));
  }
}

Index Molecule::bondUniqueId(const BondType& b) const
{
  if (b.molecule() != this)
    return MaxIndex;
  return findBondUniqueId(b.index());
}

Index Molecule::bondUniqueId(Index b) const
{
  return findBondUniqueId(b);
}

void Molecule::emitChanged(unsigned int change)
{
  if (change != NoChange)
    emit changed(change);
}

Index Molecule::findAtomUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_atomUniqueIds.size()); ++i)
    if (m_atomUniqueIds[i] == index)
      return i;
  return MaxIndex;
}

Index Molecule::findBondUniqueId(Index index) const
{
  for (Index i = 0; i < static_cast<Index>(m_bondUniqueIds.size()); ++i)
    if (m_bondUniqueIds[i] == index)
      return i;
  return MaxIndex;
}

RWMolecule* Molecule::undoMolecule()
{
  return m_undoMolecule;
}

} // end QtGui namespace
} // end Avogadro namespace
