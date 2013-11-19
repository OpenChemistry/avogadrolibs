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

#include "molecule.h"

namespace Avogadro {
namespace QtGui {

/**
 * @class PersistentAtom persistentatom.h <avogadro/qtcore/persistentatom.h>
 * @brief The PersistentAtom object provides a container for a persistent atom
 * reference that can be held onto. The atom() method gets the underlying atom
 * using the unique ID mechanism of the molecule.
 */

class AVOGADROQTGUI_EXPORT PersistentAtom
{
public:
  /**
   * @brief Create a persistent atom, with the specified unique id.
   * @param m The molecule the persistent atom belongs to.
   * @param uniqueId The unique identifier for the atom.
   */
  PersistentAtom(Molecule *m = NULL, Index uniqueId = -1)
    : m_molecule(m), m_uniqueId(uniqueId)
  {
  }

  /**
   * @brief Set the molecule and unique ID for the persistent object.
   * @param m The molecule that contains the atom.
   * @param uniqueId The unique ID of the atom.
   */
  void set(Molecule *m, Index uniqueId);

  /**
   * @return True if the persistent atom is valid.
   */
  bool isValid() const;

  /**
   * @return The molecule the atom is a part of.
   */
  Molecule* molecule() const { return m_molecule; }

  /**
   * @brief The persistent unique ID of the atom.
   * @return The unique ID of the atom.
   */
  Index uniqueIdentifier() const { return m_uniqueId; }

  /**
   * @brief Obtain the atom being held by the persistent object.
   * @return A reference to the atom held by the object.
   */
  Core::Atom atom() const;

private:
  Molecule *m_molecule;
  Index m_uniqueId;
};

inline void PersistentAtom::set(Molecule *m, Index uniqueId)
{
  m_molecule = m;
  m_uniqueId = uniqueId;
}

inline bool PersistentAtom::isValid() const
{
  return atom().isValid();
}

inline Core::Atom PersistentAtom::atom() const
{
  return m_molecule->atomByUniqueId(m_uniqueId);
}

} // End of QtGui namespace
} // End of Avogadro namespace

#endif // AVOGADRO_QTGUI_PERSISTENTATOM_H
