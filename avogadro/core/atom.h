/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ATOM_H
#define AVOGADRO_CORE_ATOM_H

#include "avogadrocore.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

enum AtomHybridization
{
  PerceivedOctaheadral = -6,
  PerceivedTrigonalBipyramidal = -5,
  PerceivedSquarePlanar = -4,
  PerceivedSP3 = -3,
  PerceivedSP2 = -2,
  PerceivedSP = -1,
  HybridizationUnknown = 0,
  SP = 1,
  SP2 = 2,
  SP3 = 3,
  SquarePlanar = 4,
  TrigonalBipyramidal = 5,
  Octahedral = 6
};

enum AtomicNumber : unsigned char
{
  Hydrogen = 1,
  Carbon = 6,
  Nitrogen = 7,
  Oxygen = 8
};

/**
 * @class Atom atom.h <avogadro/core/atom.h>
 * The atom class represents an atom in a molecule.
 * To use the appropriate atom implementation for a specific molecule
 * implementation, use the [MoleculeClass]::AtomType typedef.
 */
template <class Molecule_T>
class AtomTemplate
{
public:
  typedef Molecule_T MoleculeType;

  /** Creates a new, invalid atom object. */
  AtomTemplate();

  /**
   * Creates a new atom object representing the atom at index @p i in molecule
   * @p m.
   */
  AtomTemplate(MoleculeType* m, Index i);

  /**
   * @return True if @a this and @a other share the same index and molecule.
   */
  bool operator==(const AtomTemplate<MoleculeType>& other) const;

  /**
   * @return True if @a this and @a other do not share the same index or
   * molecule.
   */
  bool operator!=(const AtomTemplate<MoleculeType>& other) const;

  /**
   * Prefix increment operator. Increment this Atom's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  AtomTemplate<MoleculeType>& operator++();

  /**
   * Postfix increment operator. Increment this Atom's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  AtomTemplate<MoleculeType> operator++(int);

  /**
   * Prefix decrement operator. Decrement this Atom's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  AtomTemplate<MoleculeType>& operator--();

  /**
   * Postfix decrement operator. Decrement this Atom's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  AtomTemplate<MoleculeType> operator--(int);

  /**
   * @return True if the molecule is set and the index is less than the number
   * of atoms.
   */
  bool isValid() const;

  /**
   * @return The molecule that contains this Atom.
   */
  MoleculeType* molecule() const;

  /**
   * @return The index of this atom in molecule().
   */
  Index index() const;

  /**
   * The proton count of the atom.
   * @{
   */
  void setAtomicNumber(unsigned char num);
  unsigned char atomicNumber() const;
  /** @} */

  /**
   * The 2D position of this atom.
   * @note Not all molecule types support 2D positions. If the current
   * MoleculeType class does not, calling this method will result in a
   * compilation error.
   * @{
   */
  void setPosition2d(const Vector2& pos);
  Vector2 position2d() const;
  /** @} */

  /**
   * The 3D position of this atom.
   * @{
   */
  void setPosition3d(const Vector3& pos);
  Vector3 position3d() const;
  /** @} */

  /**
   * The hybridization / coordination of this atom
   * @{
   */
  void setHybridization(AtomHybridization hyb);
  AtomHybridization hybridization() const;
  /** @} */

  /**
   * The formal charge of this atom
   * @{
   */
  void setFormalCharge(signed char charge);
  signed char formalCharge() const;
  /** @} */

  /**
   * The color of this atom
   * @{
   */
  void setColor(Vector3ub color);
  Vector3ub color() const;
  /** @} */

  /**
   * The layer of this atom
   * @{
   */
  void setLayer(size_t layer);
  size_t layer() const;
  /** @} */

  /**
   * Is the atom selected.
   * {@
   */
  void setSelected(bool selected);
  bool selected() const;
  /** @} */

  /**
   * The force on this atom.
   * {@
   */
  void setForceVector(const Vector3& force);
  Vector3 forceVector() const;

  void setLabel(const std::string& label);
  std::string label() const;
  /** @} */

private:
  MoleculeType* m_molecule;
  Index m_index;
};

template <class Molecule_T>
AtomTemplate<Molecule_T>::AtomTemplate()
  : m_molecule(nullptr), m_index(MaxIndex)
{}

template <class Molecule_T>
AtomTemplate<Molecule_T>::AtomTemplate(MoleculeType* m, Index i)
  : m_molecule(m), m_index(i)
{}

template <class Molecule_T>
bool AtomTemplate<Molecule_T>::operator==(
  const AtomTemplate<MoleculeType>& other) const
{
  return m_molecule == other.m_molecule && m_index == other.m_index;
}

template <class Molecule_T>
bool AtomTemplate<Molecule_T>::operator!=(
  const AtomTemplate<MoleculeType>& other) const
{
  return m_molecule != other.m_molecule || m_index != other.m_index;
}

template <class Molecule_T>
AtomTemplate<Molecule_T>& AtomTemplate<Molecule_T>::operator++()
{
  ++m_index;
  return *this;
}

template <class Molecule_T>
AtomTemplate<Molecule_T> AtomTemplate<Molecule_T>::operator++(int)
{
  AtomTemplate<MoleculeType> result(m_molecule, m_index++);
  return result;
}

template <class Molecule_T>
AtomTemplate<Molecule_T>& AtomTemplate<Molecule_T>::operator--()
{
  --m_index;
  return *this;
}

template <class Molecule_T>
AtomTemplate<Molecule_T> AtomTemplate<Molecule_T>::operator--(int)
{
  AtomTemplate<MoleculeType> result(m_molecule, m_index--);
  return result;
}

template <class Molecule_T>
bool AtomTemplate<Molecule_T>::isValid() const
{
  return m_molecule && m_index < m_molecule->atomCount();
}

template <class Molecule_T>
typename AtomTemplate<Molecule_T>::MoleculeType*
AtomTemplate<Molecule_T>::molecule() const
{
  return m_molecule;
}

template <class Molecule_T>
Index AtomTemplate<Molecule_T>::index() const
{
  return m_index;
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setAtomicNumber(unsigned char num)
{
  m_molecule->setAtomicNumber(m_index, num);
}

template <class Molecule_T>
unsigned char AtomTemplate<Molecule_T>::atomicNumber() const
{
  return m_molecule->atomicNumber(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setPosition2d(const Vector2& pos)
{
  m_molecule->setAtomPosition2d(m_index, pos);
}

template <class Molecule_T>
Vector2 AtomTemplate<Molecule_T>::position2d() const
{
  return m_molecule->atomPositions2d().size() > 0
           ? m_molecule->atomPositions2d()[m_index]
           : Vector2::Zero();
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setPosition3d(const Vector3& pos)
{
  m_molecule->setAtomPosition3d(m_index, pos);
}

template <class Molecule_T>
Vector3 AtomTemplate<Molecule_T>::position3d() const
{
  return m_molecule->atomPositions3d().size() > 0
           ? m_molecule->atomPositions3d()[m_index]
           : Vector3::Zero();
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setHybridization(AtomHybridization hyb)
{
  m_molecule->setHybridization(m_index, hyb);
}

template <class Molecule_T>
AtomHybridization AtomTemplate<Molecule_T>::hybridization() const
{
  return m_molecule->hybridization(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setFormalCharge(signed char charge)
{
  m_molecule->setFormalCharge(m_index, charge);
}

template <class Molecule_T>
signed char AtomTemplate<Molecule_T>::formalCharge() const
{
  return m_molecule->formalCharge(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setColor(Vector3ub color)
{
  m_molecule->setColor(m_index, std::move(color));
}

template <class Molecule_T>
Vector3ub AtomTemplate<Molecule_T>::color() const
{
  return m_molecule->color(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setLayer(size_t layer)
{
  m_molecule->setLayer(m_index, layer);
}

template <class Molecule_T>
size_t AtomTemplate<Molecule_T>::layer() const
{
  return m_molecule->layer(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setSelected(bool selected)
{
  m_molecule->setAtomSelected(m_index, selected);
}

template <class Molecule_T>
bool AtomTemplate<Molecule_T>::selected() const
{
  return m_molecule->atomSelected(m_index);
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setForceVector(const Vector3& force)
{
  m_molecule->setForceVector(m_index, force);
}

template <class Molecule_T>
Vector3 AtomTemplate<Molecule_T>::forceVector() const
{
  return m_molecule->forceVectors().size() > 0
           ? m_molecule->forceVectors()[m_index]
           : Vector3::Zero();
}

template <class Molecule_T>
void AtomTemplate<Molecule_T>::setLabel(const std::string& label)
{
  m_molecule->setLabel(m_index, label);
}

template <class Molecule_T>
std::string AtomTemplate<Molecule_T>::label() const
{
  return m_molecule->label(m_index);
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ATOM_H
