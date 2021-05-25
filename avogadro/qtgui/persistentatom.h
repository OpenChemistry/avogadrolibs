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

#ifndef AVOGADRO_QTGUI_PERSISTENTATOM_H
#define AVOGADRO_QTGUI_PERSISTENTATOM_H

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtGui {

/**
 * @class PersistentAtom persistentatom.h <avogadro/qtcore/persistentatom.h>
 * @brief The PersistentAtom object provides a container for a persistent atom
 * reference that can be held onto. The atom() method gets the underlying atom
 * using the unique ID mechanism of the molecule.
 */
template <typename Molecule_T>
class PersistentAtom
{
public:
  typedef Molecule_T MoleculeType;
  typedef typename Molecule_T::AtomType AtomType;

  /**
   * @brief Create a persistent atom, with the specified unique id.
   * @param m The molecule the persistent atom belongs to.
   * @param uniqueId The unique identifier for the atom.
   */
  explicit PersistentAtom(MoleculeType* m = nullptr, Index uniqueId = MaxIndex)
    : m_molecule(m), m_uniqueId(uniqueId)
  {
  }

  /**
   * @brief Create a persistent atom from a standard atom object.
   * @param a The atom that a persistent reference should be created for.
   */
  explicit PersistentAtom(const AtomType& a);

  /**
   * @brief Set the molecule and unique ID for the persistent object.
   * @param m The molecule that contains the atom.
   * @param uniqueId The unique ID of the atom.
   */
  void set(MoleculeType* m, Index uniqueId);

  /**
   * @brief Set the persistent atom from a standard atom object.
   * @param a The atom that a persistent reference should be created for.
   */
  void set(const AtomType& a);

  /**
   * @brief Reset the object to an invalid state.
   */
  void reset();

  /**
   * @return True if the persistent atom is valid.
   */
  bool isValid() const;

  /**
   * @return The molecule the atom is a part of.
   */
  MoleculeType* molecule() const { return m_molecule; }

  /**
   * @brief The persistent unique ID of the atom.
   * @return The unique ID of the atom.
   */
  Index uniqueIdentifier() const { return m_uniqueId; }

  /**
   * @brief Obtain the atom being held by the persistent object.
   * @return A reference to the atom held by the object.
   */
  AtomType atom() const;

private:
  MoleculeType* m_molecule;
  Index m_uniqueId;
};

template <typename Molecule_T>
PersistentAtom<Molecule_T>::PersistentAtom(const AtomType& a)
  : m_molecule(dynamic_cast<MoleculeType*>(a.molecule()))
{
  m_uniqueId = m_molecule ? m_molecule->atomUniqueId(a) : MaxIndex;
}

template <typename Molecule_T>
void PersistentAtom<Molecule_T>::set(MoleculeType* m, Index uniqueId)
{
  m_molecule = m;
  m_uniqueId = uniqueId;
}

template <typename Molecule_T>
void PersistentAtom<Molecule_T>::set(const AtomType& a)
{
  m_molecule = dynamic_cast<MoleculeType*>(a.molecule());
  m_uniqueId = m_molecule ? m_molecule->atomUniqueId(a) : MaxIndex;
}

template <typename Molecule_T>
void PersistentAtom<Molecule_T>::reset()
{
  set(nullptr, MaxIndex);
}

template <typename Molecule_T>
bool PersistentAtom<Molecule_T>::isValid() const
{
  return atom().isValid();
}

template <typename Molecule_T>
typename Molecule_T::AtomType PersistentAtom<Molecule_T>::atom() const
{
  return m_molecule ? m_molecule->atomByUniqueId(m_uniqueId) : AtomType();
}

} // End of QtGui namespace
} // End of Avogadro namespace

#endif // AVOGADRO_QTGUI_PERSISTENTATOM_H
