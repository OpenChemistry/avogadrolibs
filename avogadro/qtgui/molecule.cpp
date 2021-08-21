/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecule.h"
#include "rwmolecule.h"

#include <iostream>

namespace Avogadro {
namespace QtGui {

using std::swap;

Molecule::Molecule(QObject* parent_)
  : QObject(parent_),
    m_undoMolecule(new RWMolecule(*this, this)), Core::Molecule()
{
  m_undoMolecule->setInteractive(true);
}

Molecule::Molecule(const Molecule& other)
  : QObject(), Core::Molecule(other),
    m_undoMolecule(new RWMolecule(*this, this))
{
  m_undoMolecule->setInteractive(true);
  // Now assign the unique ids
  for (Index i = 0; i < atomCount(); i++)
    m_atomUniqueIds.push_back(i);

  for (Index i = 0; i < bondCount(); i++)
    m_bondUniqueIds.push_back(i);
}

Molecule::Molecule(const Core::Molecule& other)
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

Molecule::~Molecule() {}

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

Molecule::AtomType Molecule::addAtom(unsigned char number, Vector3 position3d,
                                     Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_atomUniqueIds.size())) {
    m_atomUniqueIds.push_back(atomCount());
    return Core::Molecule::addAtom(number, position3d);
  } else {
    auto atom = Molecule::addAtom(number, uniqueId);
    if (atom.isValid())
      atom.setPosition3d(position3d);
    return atom;
  }
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
  Index newSize = static_cast<Index>(atomCount() - 1);

  // Before removing the atom we must first remove any bonds to it.
  Core::Molecule::removeAtom(index);

  if (index != newSize) {
    // movedAtomUID
    uniqueId = findAtomUniqueId(newSize);
    assert(uniqueId != MaxIndex);
    m_atomUniqueIds[uniqueId] = index;
  }
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

void Molecule::addBonds(const Core::Array<std::pair<Index, Index>>& bonds,
                        const Core::Array<unsigned char>& orders)
{
  assert(orders.size() == bonds.size());
  for (Index i = 0; i < orders.size(); ++i) {
    addBond(bonds[i].first, bonds[i].second, orders[i]);
  }
}
void Molecule::swapBond(Index a, Index b)
{
  Index uniqueA = findBondUniqueId(a);
  Index uniqueB = findBondUniqueId(b);
  assert(uniqueA != MaxIndex && uniqueB != MaxIndex);
  swap(m_bondUniqueIds[uniqueA], m_bondUniqueIds[uniqueB]);
  Core::Molecule::swapBond(a, b);
}

void Molecule::swapAtom(Index a, Index b)
{
  if (a == b) {
    return;
  }
  Index uniqueA = findAtomUniqueId(a);
  Index uniqueB = findAtomUniqueId(b);
  assert(uniqueA != MaxIndex && uniqueB != MaxIndex);
  swap(m_atomUniqueIds[uniqueA], m_atomUniqueIds[uniqueB]);
  Core::Molecule::swapAtom(a, b);
}

Molecule::BondType Molecule::addBond(Index a, Index b,
                                     unsigned char order, Index uniqueId)
{
  if (uniqueId >= static_cast<Index>(m_bondUniqueIds.size()) ||
      m_bondUniqueIds[uniqueId] != MaxIndex) {
    return BondType();
  }

  m_bondUniqueIds[uniqueId] = bondCount();
  return Core::Molecule::addBond(a, b, order);
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

  Index newSize = static_cast<Index>(bondCount() - 1);
  if (index != newSize) {
    Index movedBondUID = findBondUniqueId(newSize);
    assert(movedBondUID != MaxIndex);
    m_bondUniqueIds[movedBondUID] = index;
  }
  Core::Molecule::removeBond(index);
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

} // namespace QtGui
} // namespace Avogadro
