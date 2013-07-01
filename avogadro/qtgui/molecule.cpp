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

Molecule::~Molecule()
{
}

Core::Atom Molecule::addAtom(unsigned char atomicNumber)
{
  m_atomUniqueIds.push_back(static_cast<int>(atomCount()));
  Core::Atom a = Core::Molecule::addAtom(atomicNumber);
  return a;
}

Core::Atom Molecule::addAtom(unsigned char atomicNumber, int uniqueId)
{
  if (uniqueId >= static_cast<int>(m_atomUniqueIds.size())
      || m_atomUniqueIds[uniqueId] != -1) {
    return Core::Atom();
  }

  m_atomUniqueIds[uniqueId] = static_cast<int>(atomCount());
  Core::Atom a = Core::Molecule::addAtom(atomicNumber);
  return a;
}

bool Molecule::removeAtom(size_t index)
{
  if (index >= atomCount())
    return false;
  int uniqueId = findAtomUniqueId(index);
  if (uniqueId < 0)
    return false;

  m_atomUniqueIds[uniqueId] = -1; // Unique ID of an atom that was removed.

  // Before removing the atom we must first remove any bonds to it.
  std::vector<Core::Bond> atomBonds = Core::Molecule::bonds(atom(index));
  while (atomBonds.size()) {
    removeBond(atomBonds.back());
    atomBonds = Core::Molecule::bonds(atom(index));
  }

  size_t newSize = m_atomicNumbers.size() - 1;
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
      std::pair<size_t, size_t> bondPair = m_bondPairs[currentBond.index()];
      if (bondPair.first == newSize)
        bondPair.first = index;
      else if (bondPair.second == newSize)
        bondPair.second = index;
      m_bondPairs[currentBond.index()] = bondPair;
    }

    int movedAtomUID = findAtomUniqueId(newSize);
    assert(movedAtomUID != -1);
    m_atomUniqueIds[movedAtomUID] = static_cast<int>(index);
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

Core::Atom Molecule::atomByUniqueId(int uniqueId)
{
  if (uniqueId >= static_cast<int>(m_atomUniqueIds.size())
      || m_atomUniqueIds[uniqueId] == -1) {
    return Core::Atom();
  }
  else {
    return Core::Atom(this, static_cast<size_t>(m_atomUniqueIds[uniqueId]));
  }
}

int Molecule::atomUniqueId(const Core::Atom &a) const
{
  if (a.molecule() != this)
    return -1;
  return findAtomUniqueId(a.index());
}

Core::Bond Molecule::addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder)
{
  m_bondUniqueIds.push_back(static_cast<int>(bondCount()));
  Core::Bond bond_ = Core::Molecule::addBond(a, b, bondOrder);
  return bond_;
}

Core::Bond Molecule::addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder, int uniqueId)
{
  if (uniqueId >= static_cast<int>(m_bondUniqueIds.size())
      || m_bondUniqueIds[uniqueId] != -1) {
    return Core::Bond();
  }

  m_bondUniqueIds[uniqueId] = static_cast<int>(bondCount());
  Core::Bond bond_ = Core::Molecule::addBond(a, b, bondOrder);
  return bond_;
}

bool Molecule::removeBond(size_t index)
{
  if (index >= bondCount())
    return false;
  int uniqueId = findBondUniqueId(index);
  if (uniqueId < 0)
    return false;

  m_bondUniqueIds[uniqueId] = -1; // Unique ID of a bond that was removed.

  size_t newSize = m_bondOrders.size() - 1;
  if (index != newSize) {
    // We need to move the last bond to this position, and update its unique ID.
    m_bondOrders[index] = m_bondOrders.back();
    m_bondPairs[index] = m_bondPairs.back();

    int movedBondUID = findBondUniqueId(newSize);
    assert(movedBondUID != -1);
    m_bondUniqueIds[movedBondUID] = static_cast<int>(index);
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

Core::Bond Molecule::bondByUniqueId(int uniqueId)
{
  if (uniqueId >= static_cast<int>(m_bondUniqueIds.size())
      || m_bondUniqueIds[uniqueId] == -1) {
    return Core::Bond();
  }
  else {
    return Core::Bond(this, static_cast<size_t>(m_bondUniqueIds[uniqueId]));
  }
}

int Molecule::bondUniqueId(const Core::Bond &b) const
{
  if (b.molecule() != this)
    return -1;
  return findBondUniqueId(b.index());
}

void Molecule::emitChanged(unsigned int change)
{
  if (change != NoChange)
    emit changed(change);
}

inline int Molecule::findAtomUniqueId(size_t index) const
{
  for (size_t i = 0; i < m_atomUniqueIds.size(); ++i)
    if (m_atomUniqueIds[i] == static_cast<int>(index))
      return static_cast<int>(i);
  return -1;
}

inline int Molecule::findBondUniqueId(size_t index) const
{
  for (size_t i = 0; i < m_bondUniqueIds.size(); ++i)
    if (m_bondUniqueIds[i] == static_cast<int>(index))
      return static_cast<int>(i);
  return -1;
}

} // end QtGui namespace
} // end Avogadro namespace
