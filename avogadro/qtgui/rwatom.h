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

#ifndef RWATOM_H
#define RWATOM_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace QtGui {

template <class Molecule_T>
class Atom
{
public:
  typedef Molecule_T MoleculeType;

  Atom();
  Atom(MoleculeType *m, Index i);

  bool operator==(const Atom<MoleculeType> &other) const;
  bool operator!=(const Atom<MoleculeType> &other) const;

  bool isValid() const;

  MoleculeType* molecule() const;
  Index index() const;

  void setAtomicNumber(unsigned char num);
  unsigned char atomicNumber() const;

  void setPosition2d(const Vector2 &pos);
  Vector2 position2d() const;
  void position2d(Vector2 &pos);

  void setPosition3d(const Vector3 &pos);
  Vector3 position3d() const;
  void position3d(Vector3 &pos);

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
  m_molecule->setPosition2d(m_index, pos);
}

template <class Molecule_T>
Vector2 Atom<Molecule_T>::position2d() const
{
  return m_molecule->positions2d()[m_index];
}

template <class Molecule_T>
void Atom<Molecule_T>::position2d(Vector2 &pos)
{
  pos = m_molecule->positions2d()[m_index];
}

template <class Molecule_T>
void Atom<Molecule_T>::setPosition3d(const Vector3 &pos)
{
  m_molecule->setPosition3d(m_index, pos);
}

template <class Molecule_T>
Vector3 Atom<Molecule_T>::position3d() const
{
  return m_molecule->positions3d()[m_index];
}

template <class Molecule_T>
void Atom<Molecule_T>::position3d(Vector3 &pos)
{
  pos = m_molecule->positions3d()[m_index];
}

} // end namespace QtGui
} // end namespace Avogadro

#endif // RWATOM_H
