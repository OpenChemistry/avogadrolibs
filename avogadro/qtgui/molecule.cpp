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

#include "mesh.h"
#include "color3f.h"

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
  m_atomUniqueIds.push_back(atomCount());
  Core::Atom a = Core::Molecule::addAtom(atomicNumber);
  emit changed(Atoms | Added);
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
    m_atomUniqueIds[movedAtomUID] = index;
  }
  // Resize the arrays for the smaller molecule.
  if (m_positions2d.size() == m_atomicNumbers.size())
    m_positions2d.resize(newSize);
  if (m_positions3d.size() == m_atomicNumbers.size())
    m_positions3d.resize(newSize);
  m_atomicNumbers.resize(newSize);

  // Emit a signal to show the molecule has changed and return success.
  emit changed(Atoms | Removed);
  return true;
}

bool Molecule::removeAtom(const Core::Atom &atom_)
{
  return removeAtom(atom_.index());
}

void Molecule::clearAtoms()
{
  while (atomCount() > 0)
    removeAtom(static_cast<size_t>(0));
}

Core::Bond Molecule::addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder)
{
  m_bondUniqueIds.push_back(bondCount());
  Core::Bond bond_ = Core::Molecule::addBond(a, b, bondOrder);
  emit changed(Bonds | Added);
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
    m_bondUniqueIds[movedBondUID] = index;
  }

  // Resize the arrays for the smaller molecule.
  m_bondOrders.resize(newSize);
  m_bondPairs.resize(newSize);

  // Emit a signal to show the molecule has changed and return success.
  emit changed(Bonds | Removed);
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

void Molecule::clearBonds()
{
  while (bondCount())
    removeBond(static_cast<size_t>(0));
}

Mesh* Molecule::addMesh()
{
  m_meshes.push_back(new Mesh);
  return m_meshes.back();
}

Mesh* Molecule::mesh(size_t index)
{
  if (index < m_meshes.size())
    return m_meshes[index];
  else
    return NULL;
}

const Mesh* Molecule::mesh(size_t index) const
{
  if (index < m_meshes.size())
    return m_meshes[index];
  else
    return NULL;
}

void Molecule::emitChanged(unsigned int change)
{
  emit changed(change);
}

int Molecule::findAtomUniqueId(size_t index) const
{
  for (size_t i = 0; i < m_atomUniqueIds.size(); ++i)
    if (m_atomUniqueIds[i] == static_cast<int>(index))
      return static_cast<int>(i);
  return -1;
}

int Molecule::findBondUniqueId(size_t index) const
{
  for (size_t i = 0; i < m_bondUniqueIds.size(); ++i)
    if (m_bondUniqueIds[i] == static_cast<int>(index))
      return static_cast<int>(i);
  return -1;
}

} // end QtGui namespace
} // end Avogadro namespace
