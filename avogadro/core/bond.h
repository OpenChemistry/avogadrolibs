/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BOND_H
#define AVOGADRO_CORE_BOND_H

#include "avogadrocore.h"

#include "atom.h"

namespace Avogadro {
namespace Core {

/**
 * @class Bond bond.h <avogadro/core/bond.h>
 * The Bond class represents a bond in a molecule.
 * To use the appropriate bond implementation for a specific molecule
 * implementation, use the [MoleculeClass]::BondType typedef.
 */
template <class Molecule_T>
class BondTemplate
{
public:
  typedef Molecule_T MoleculeType;
  typedef typename Molecule_T::AtomType AtomType;

  /** Creates a new, invalid bond object. */
  BondTemplate();

  /**
   * Creates a bond object representing a bond at index @p i in molecule @p m.
   */
  BondTemplate(MoleculeType* m, Index i);

  /**
   * @return True if @a this and @a other share the same index and molecule.
   */
  bool operator==(const BondTemplate<MoleculeType>& other) const;

  /**
   * @return True if @a this and @a other do not share the same index or
   * molecule.
   */
  bool operator!=(const BondTemplate<MoleculeType>& other) const;

  /**
   * Prefix increment operator. Increment this Bond's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  BondTemplate<MoleculeType>& operator++();

  /**
   * Postfix increment operator. Increment this Bond's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  BondTemplate<MoleculeType> operator++(int);

  /**
   * Prefix decrement operator. Decrement this Bond's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  BondTemplate<MoleculeType>& operator--();

  /**
   * Postfix decrement operator. Decrement this Bond's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  BondTemplate<MoleculeType> operator--(int);

  /**
   * @return True if the molecule is set and the index is less than the number
   * of bonds.
   */
  bool isValid() const;

  /**
   * @return The molecule that contains this Bond.
   */
  MoleculeType* molecule() const;

  /**
   * @return The index of this bond in molecule().
   */
  Index index() const;

  /**
   * An atom in the bond, such that atom1().index() < atom2.index().
   * @{
   */
  AtomType atom1() const;
  AtomType atom2() const;
  /** @} */

  /**
   * @return The atom in the bond such that returned.index() != index.
   */
  AtomType getOtherAtom(Index index) const;

  /**
   * @return The atom in the bond such that returned.index() != atom.index().
   */
  AtomType getOtherAtom(AtomType atom) const;

  /**
   * The bond's order (single = 1, double = 2, etc.)
   * @{
   */
  void setOrder(unsigned char o);
  unsigned char order() const;
  /** @} */

private:
  MoleculeType* m_molecule;
  Index m_index;
};

template <class Molecule_T>
BondTemplate<Molecule_T>::BondTemplate()
  : m_molecule(nullptr), m_index(MaxIndex)
{
}

template <class Molecule_T>
BondTemplate<Molecule_T>::BondTemplate(MoleculeType* m, Index i)
  : m_molecule(m), m_index(i)
{
}

template <class Molecule_T>
bool BondTemplate<Molecule_T>::operator==(
  const BondTemplate<MoleculeType>& other) const
{
  return m_molecule == other.m_molecule && m_index == other.m_index;
}

template <class Molecule_T>
bool BondTemplate<Molecule_T>::operator!=(
  const BondTemplate<MoleculeType>& other) const
{
  return m_molecule != other.m_molecule || m_index != other.m_index;
}

template <class Molecule_T>
BondTemplate<Molecule_T>& BondTemplate<Molecule_T>::operator++()
{
  ++m_index;
  return *this;
}

template <class Molecule_T>
BondTemplate<Molecule_T> BondTemplate<Molecule_T>::operator++(int)
{
  BondTemplate<MoleculeType> result(m_molecule, m_index++);
  return result;
}

template <class Molecule_T>
BondTemplate<Molecule_T>& BondTemplate<Molecule_T>::operator--()
{
  --m_index;
  return *this;
}

template <class Molecule_T>
BondTemplate<Molecule_T> BondTemplate<Molecule_T>::operator--(int)
{
  BondTemplate<MoleculeType> result(m_molecule, m_index--);
  return result;
}

template <class Molecule_T>
bool BondTemplate<Molecule_T>::isValid() const
{
  return m_molecule && m_index < m_molecule->bondCount();
}

template <class Molecule_T>
typename BondTemplate<Molecule_T>::MoleculeType*
BondTemplate<Molecule_T>::molecule() const
{
  return m_molecule;
}

template <class Molecule_T>
Index BondTemplate<Molecule_T>::index() const
{
  return m_index;
}

template <class Molecule_T>
typename BondTemplate<Molecule_T>::AtomType BondTemplate<Molecule_T>::atom1()
  const
{
  return AtomType(m_molecule, m_molecule->bondPairs()[m_index].first);
}

template <class Molecule_T>
typename BondTemplate<Molecule_T>::AtomType BondTemplate<Molecule_T>::atom2()
  const
{
  return AtomType(m_molecule, m_molecule->bondPairs()[m_index].second);
}

template <class Molecule_T>
typename BondTemplate<Molecule_T>::AtomType BondTemplate<Molecule_T>::getOtherAtom(Index index)
  const
{
  if (atom1().index() == index)
    return atom2();
  else
    return atom1();
}

template <class Molecule_T>
typename BondTemplate<Molecule_T>::AtomType BondTemplate<Molecule_T>::getOtherAtom(
    BondTemplate<Molecule_T>::AtomType atom
) const
{
  return getOtherAtom(atom.index());
}

template <class Molecule_T>
void BondTemplate<Molecule_T>::setOrder(unsigned char o)
{
  m_molecule->setBondOrder(m_index, o);
}

template <class Molecule_T>
unsigned char BondTemplate<Molecule_T>::order() const
{
  return m_molecule->bondOrders()[m_index];
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_BOND_H
