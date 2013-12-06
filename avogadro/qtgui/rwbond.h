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

#ifndef RWBOND_H
#define RWBOND_H

#include <avogadro/core/avogadrocore.h>

#include "rwatom.h"

namespace Avogadro {
namespace QtGui {

/**
 * A templated version of Core::Bond. This class will eventually replace that
 * one. For now, refer to that class's documentation.
 */
template <class Molecule_T>
class Bond
{
public:
  typedef Molecule_T MoleculeType;
  typedef Atom<Molecule_T> AtomType;

  Bond();
  Bond(MoleculeType *m, Index i);

  bool operator==(const Bond<MoleculeType> &other) const;
  bool operator!=(const Bond<MoleculeType> &other) const;

  bool isValid() const;

  MoleculeType* molecule() const;
  Index index() const;

  AtomType atom1() const;
  AtomType atom2() const;

  void setOrder(unsigned char o);
  unsigned char order() const;

private:
  MoleculeType *m_molecule;
  Index m_index;
};

template <class Molecule_T>
Bond<Molecule_T>::Bond()
  : m_molecule(NULL),
    m_index(MaxIndex)
{
}

template <class Molecule_T>
Bond<Molecule_T>::Bond(MoleculeType *m, Index i)
  : m_molecule(m),
    m_index(i)
{
}

template <class Molecule_T>
bool Bond<Molecule_T>::operator==(const Bond<MoleculeType> &other) const
{
  return m_molecule == other.m_molecule && m_index == other.m_index;
}

template <class Molecule_T>
bool Bond<Molecule_T>::operator!=(const Bond<MoleculeType> &other) const
{
  return m_molecule != other.m_molecule || m_index != other.m_index;
}

template <class Molecule_T>
bool Bond<Molecule_T>::isValid() const
{
  return m_molecule && m_index < m_molecule->bondCount();
}

template <class Molecule_T>
typename Bond<Molecule_T>::MoleculeType *Bond<Molecule_T>::molecule() const
{
  return m_molecule;
}

template <class Molecule_T>
Index Bond<Molecule_T>::index() const
{
  return m_index;
}

template <class Molecule_T>
typename Bond<Molecule_T>::AtomType Bond<Molecule_T>::atom1() const
{
  return AtomType(m_molecule, m_molecule->bondPairs()[m_index].first);
}

template <class Molecule_T>
typename Bond<Molecule_T>::AtomType Bond<Molecule_T>::atom2() const
{
  return AtomType(m_molecule, m_molecule->bondPairs()[m_index].second);
}

template <class Molecule_T>
void Bond<Molecule_T>::setOrder(unsigned char o)
{
  m_molecule->setBondOrder(m_index, o);
}

template <class Molecule_T>
unsigned char Bond<Molecule_T>::order() const
{
  return m_molecule->bondOrders()[m_index];
}

} // end namespace QtGui
} // end namespace Avogadro

#endif // RWBOND_H
