/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_ATOM_H
#define AVOGADRO_CORE_ATOM_H

#include "avogadrocore.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

/**
 * @class Atom atom.h <avogadro/core/atom.h>
 * The atom class represents an atom in a molecule.
 * To use the appropriate atom implementation for a specific molecule
 * implementation, use the [MoleculeClass]::AtomType typedef.
 */
template <class Molecule_T>
class Atom
{
public:
  typedef Molecule_T MoleculeType;

  /** Creates a new, invalid atom object. */
  Atom();

  /**
   * Creates a new atom object representing the atom at index @p i in molecule
   * @p m.
   */
  Atom(MoleculeType *m, Index i);

  /**
   * @return True if @a this and @a other share the same index and molecule.
   */
  bool operator==(const Atom<MoleculeType> &other) const;

  /**
   * @return True if @a this and @a other do not share the same index or
   * molecule.
   */
  bool operator!=(const Atom<MoleculeType> &other) const;

  /**
   * Prefix increment operator. Increment this Atom's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  Atom<MoleculeType>& operator++();

  /**
   * Postfix increment operator. Increment this Atom's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  Atom<MoleculeType> operator++(int);

  /**
   * Prefix decrement operator. Decrement this Atom's index by 1 and return a
   * self-reference. Check isValid() before calling any other methods.
   */
  Atom<MoleculeType>& operator--();

  /**
   * Postfix decrement operator. Decrement this Atom's index by 1 and return a
   * copy of the current Atom. Check isValid() before calling any other methods.
   */
  Atom<MoleculeType> operator--(int);

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
  void setPosition2d(const Vector2 &pos);
  Vector2 position2d() const;
  /** @} */

  /**
   * The 3D position of this atom.
   * @{
   */
  void setPosition3d(const Vector3 &pos);
  Vector3 position3d() const;
  /** @} */

private:
  MoleculeType *m_molecule;
  Index m_index;
};

template <class Molecule_T>
Atom<Molecule_T>::Atom()
  : m_molecule(NULL),
    m_index(MaxIndex)
{
}

template <class Molecule_T>
Atom<Molecule_T>::Atom(MoleculeType *m, Index i)
  : m_molecule(m),
    m_index(i)
{
}

template <class Molecule_T>
bool Atom<Molecule_T>::operator==(const Atom<MoleculeType> &other) const
{
  return m_molecule == other.m_molecule && m_index == other.m_index;
}

template <class Molecule_T>
bool Atom<Molecule_T>::operator!=(const Atom<MoleculeType> &other) const
{
  return m_molecule != other.m_molecule || m_index != other.m_index;
}

template <class Molecule_T>
Atom<Molecule_T> &Atom<Molecule_T>::operator++()
{
  ++m_index;
  return *this;
}

template <class Molecule_T>
Atom<Molecule_T> Atom<Molecule_T>::operator++(int)
{
  Atom<MoleculeType> result(m_molecule, m_index++);
  return result;
}

template <class Molecule_T>
Atom<Molecule_T> &Atom<Molecule_T>::operator--()
{
  --m_index;
  return *this;
}

template <class Molecule_T>
Atom<Molecule_T> Atom<Molecule_T>::operator--(int)
{
  Atom<MoleculeType> result(m_molecule, m_index--);
  return result;
}

template <class Molecule_T>
bool Atom<Molecule_T>::isValid() const
{
  return m_molecule && m_index < m_molecule->atomCount();
}

template <class Molecule_T>
typename Atom<Molecule_T>::MoleculeType *Atom<Molecule_T>::molecule() const
{
  return m_molecule;
}

template <class Molecule_T>
Index Atom<Molecule_T>::index() const
{
  return m_index;
}

template <class Molecule_T>
void Atom<Molecule_T>::setAtomicNumber(unsigned char num)
{
  m_molecule->setAtomicNumber(m_index, num);
}

template <class Molecule_T>
unsigned char Atom<Molecule_T>::atomicNumber() const
{
  return m_molecule->atomicNumber(m_index);
}

template <class Molecule_T>
void Atom<Molecule_T>::setPosition2d(const Vector2 &pos)
{
  m_molecule->setAtomPosition2d(m_index, pos);
}

template <class Molecule_T>
Vector2 Atom<Molecule_T>::position2d() const
{
  return m_molecule->atomPositions2d().size() > 0 ?
        m_molecule->atomPositions2d()[m_index] : Vector2::Zero();
}

template <class Molecule_T>
void Atom<Molecule_T>::setPosition3d(const Vector3 &pos)
{
  m_molecule->setAtomPosition3d(m_index, pos);
}

template <class Molecule_T>
Vector3 Atom<Molecule_T>::position3d() const
{
  return m_molecule->atomPositions3d().size() > 0 ?
        m_molecule->atomPositions3d()[m_index] : Vector3::Zero();
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ATOM_H
