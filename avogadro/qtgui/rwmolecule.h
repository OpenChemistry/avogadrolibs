/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_RWMOLECULE_H
#define AVOGADRO_QTGUI_RWMOLECULE_H

#include <QtCore/QObject>
#include "avogadroqtguiexport.h"
#include "rwatom.h"
#include "rwbond.h"

#include <avogadro/core/array.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <QtGui/QUndoStack>

namespace Avogadro {
namespace QtGui {

class AVOGADROQTGUI_EXPORT RWMolecule : public QObject
{
  Q_OBJECT
public:
  typedef Atom<RWMolecule> AtomType;
  typedef Bond<RWMolecule> BondType;

  explicit RWMolecule(QObject *parent = 0);
  ~RWMolecule() AVO_OVERRIDE;

  AtomType addAtom(unsigned char atomicNumber);
  AtomType atom(Index atomId) const;
  AtomType atomByUniqueId(Index atomUId) const;
  Index atomUniqueId(Index atomId) const;
  Index atomUniqueId(const AtomType &atom) const;
  Index atomCount() const;
  Index atomCount(unsigned char atomicNumber) const;
  bool removeAtom(Index atomId);
  bool removeAtom(const AtomType &atom);
  void clearAtoms();

  const Core::Array<unsigned char>& atomicNumbers() const;
  unsigned char atomicNumber(Index atomId) const;
  bool setAtomicNumbers(const Core::Array<unsigned char> &nums);
  bool setAtomicNumber(Index atomId, unsigned char atomicNumber);

  const Core::Array<Vector3>& positions3d() const;
  Vector3 position3d(Index atomId) const;
  bool setPositions3d(const Core::Array<Vector3> &pos);
  bool setPosition3d(Index atomId, const Vector3& pos);

  BondType addBond(Index atom1, Index atom2, unsigned char order = 1);
  BondType addBond(const AtomType &atom1, const AtomType &atom2,
                   unsigned char order = 1);
  BondType bond(Index bondId) const;
  BondType bond(Index atom1, Index atom2) const;
  BondType bond(const AtomType &atom1, const AtomType &atom2) const;
  BondType bondByUniqueId(Index bondUid) const;
  Index bondUniqueId(Index bondId) const;
  Index bondUniqueId(const BondType &bond) const;
  Index bondCount() const;
  bool removeBond(Index bondId);
  bool removeBond(const BondType &bond);
  bool removeBond(Index atom1, Index atom2);
  bool removeBond(const AtomType &atom1, const AtomType &atom2);
  void clearBonds();
  Core::Array<BondType> bonds(const AtomType &atom) const;
  Core::Array<BondType> bonds(const Index &atomId) const;

  const Core::Array<unsigned char>& bondOrders() const;
  unsigned char bondOrder(Index bondId) const;
  bool setBondOrders(const Core::Array<unsigned char> &orders);
  bool setBondOrder(Index bondId, unsigned char order);

  const Core::Array<std::pair<Index, Index> >& bondPairs() const;
  std::pair<Index, Index> bondPair(Index bondId) const;
  bool setBondPairs(const Core::Array<std::pair<Index, Index> > &pairs);
  bool setBondPair(Index bondId, const std::pair<Index, Index> &pair);

  void setInteractive(bool b);
  bool interactive() const;

  QUndoStack& undoStack();
  const QUndoStack& undoStack() const;

  class UndoCommand;
  friend class UndoCommand;

protected: // methods
  Index findAtomUniqueId(Index atomId) const;
  Index findBondUniqueId(Index bondId) const;

protected: // members
  Core::Array<Index> m_atomUniqueIds;
  Core::Array<Index> m_bondUniqueIds;
  Core::Array<unsigned char> m_atomicNumbers;
  Core::Array<Vector3> m_positions3d;
  Core::Array<std::pair<Index, Index> > m_bondPairs;
  Core::Array<unsigned char> m_bondOrders;
  Core::UnitCell *m_unitCell;
  bool m_interactive;

  QUndoStack m_undoStack;
};

inline RWMolecule::AtomType RWMolecule::atom(Index atomId) const
{
  return AtomType(const_cast<RWMolecule*>(this), atomId);
}

inline RWMolecule::AtomType RWMolecule::atomByUniqueId(Index atomUId) const
{
  return atomUId < m_atomUniqueIds.size()
      ? AtomType(const_cast<RWMolecule*>(this), m_atomUniqueIds[atomUId])
      : AtomType();
}

inline Index RWMolecule::atomUniqueId(Index atomId) const
{
  return findAtomUniqueId(atomId);
}

inline Index RWMolecule::atomUniqueId(const RWMolecule::AtomType &a) const
{
  return a.molecule() == this ? findAtomUniqueId(a.index()) : MaxIndex;
}

inline Index RWMolecule::atomCount() const
{
  return m_atomicNumbers.size();
}

inline bool RWMolecule::removeAtom(const AtomType &a)
{
  return a.molecule() == this ? removeAtom(a.index()) : false;
}

inline const Core::Array<unsigned char> &RWMolecule::atomicNumbers() const
{
  return m_atomicNumbers;
}

inline unsigned char RWMolecule::atomicNumber(Index atomId) const
{
  return atomId < m_atomicNumbers.size() ? m_atomicNumbers[atomId]
                                         : InvalidElement;
}

inline const Core::Array<Vector3> &RWMolecule::positions3d() const
{
  return m_positions3d;
}

inline Vector3 RWMolecule::position3d(Index atomId) const
{
  return atomId < m_positions3d.size() ? m_positions3d[atomId] : Vector3();
}

inline RWMolecule::BondType RWMolecule::addBond(const AtomType &atom1,
                                                const AtomType &atom2,
                                                unsigned char order)
{
  if (atom1.molecule() != atom2.molecule() || atom1.molecule() != this)
    return BondType();
  return addBond(atom1.index(), atom2.index(), order);
}

inline RWMolecule::BondType RWMolecule::bond(Index bondId) const
{
  return BondType(const_cast<RWMolecule*>(this), bondId);
}

inline RWMolecule::BondType RWMolecule::bond(
    const RWMolecule::AtomType &atom1, const RWMolecule::AtomType &atom2) const
{
  if (atom1.molecule() == atom2.molecule() && atom1.molecule() == this)
    return bond(atom1.index(), atom2.index());
  return BondType();
}

inline RWMolecule::BondType RWMolecule::bondByUniqueId(Index bondUid) const
{
  return bondUid < m_bondUniqueIds.size()
      ? BondType(const_cast<RWMolecule*>(this), m_bondUniqueIds[bondUid])
      : BondType();
}

inline Index RWMolecule::bondUniqueId(Index bondId) const
{
  return findBondUniqueId(bondId);
}

inline Index RWMolecule::bondUniqueId(const RWMolecule::BondType &b) const
{
  return b.molecule() == this ? findBondUniqueId(b.index()) : MaxIndex;
}

inline Index RWMolecule::bondCount() const
{
  return m_bondOrders.size();
}

inline bool RWMolecule::removeBond(const RWMolecule::BondType &b)
{
  return b.molecule() == this ? removeBond(b.index()) : false;
}

inline bool RWMolecule::removeBond(Index atom1, Index atom2)
{
  return removeBond(bond(atom1, atom2).index());
}

inline bool RWMolecule::removeBond(const RWMolecule::AtomType &atom1,
                                   const RWMolecule::AtomType &atom2)
{
  if (atom1.molecule() != atom2.molecule() || atom1.molecule() != this)
    return false;
  return removeBond(bond(atom1.index(), atom2.index()).index());
}

inline Core::Array<RWMolecule::BondType>
RWMolecule::bonds(const RWMolecule::AtomType &a) const
{
  return a.molecule() == this ? bonds(a.index()) : Core::Array<BondType>();
}

inline Core::Array<RWMolecule::BondType>
RWMolecule::bonds(const Index &atomId) const
{
  Core::Array<RWMolecule::BondType> result;
  for (Index i = 0; i < m_bondPairs.size(); ++i)
    if (m_bondPairs[i].first == atomId || m_bondPairs[i].second == atomId)
      result.push_back(BondType(const_cast<RWMolecule*>(this), i));
  return result;
}

inline const Core::Array<unsigned char> &RWMolecule::bondOrders() const
{
  return m_bondOrders;
}

inline unsigned char RWMolecule::bondOrder(Index bondId) const
{
  return bondId < m_bondOrders.size() ? m_bondOrders[bondId] : 0;
}

inline const Core::Array<std::pair<Index, Index> > &
RWMolecule::bondPairs() const
{
  return m_bondPairs;
}

inline std::pair<Index, Index> RWMolecule::bondPair(Index bondId) const
{
  return bondId < m_bondPairs.size() ? m_bondPairs[bondId]
                                       : std::make_pair(MaxIndex, MaxIndex);
}

inline void RWMolecule::setInteractive(bool b)
{
  m_interactive = b;
}

inline bool RWMolecule::interactive() const
{
  return m_interactive;
}

inline QUndoStack &RWMolecule::undoStack()
{
  return m_undoStack;
}

inline const QUndoStack &RWMolecule::undoStack() const
{
  return m_undoStack;
}

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_RWMOLECULE_H
