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

#ifndef AVOGADRO_QTGUI_PERSISTENTBOND_H
#define AVOGADRO_QTGUI_PERSISTENTBOND_H

#include "molecule.h"

namespace Avogadro {
namespace QtGui {

/**
 * @class PersistentBond persistentbond.h <avogadro/qtcore/persistentbond.h>
 * @brief The PersistentBond object provides a container for a persistent bond
 * reference that can be held onto. The bond() method gets the underlying bond
 * using the unique ID mechanism of the molecule.
 */

class PersistentBond
{
public:
  /**
   * @brief Create a persistent bond, with the specified unique id.
   * @param m The molecule the persistent bond belongs to.
   * @param uniqueId The unique identifier for the bond.
   */
  explicit PersistentBond(Molecule *m = NULL, Index uniqueId = MaxIndex)
    : m_molecule(m), m_uniqueId(uniqueId)
  {
  }

  /**
   * @brief Create a persistent bond from a standard bond object.
   * @param b The bond that a persistent reference should be created for.
   */
  explicit PersistentBond(const Core::Bond &b);

  /**
   * @brief Set the molecule and unique ID for the persistent object.
   * @param m The molecule that contains the bond.
   * @param uniqueId The unique ID of the bond.
   */
  void set(Molecule *m, Index uniqueId);

  /**
   * @brief Set the persistent bond from a standard bond object.
   * @param b The bond that a persistent reference should be created for.
   */
  void set(const Core::Bond &b);

  /**
   * @brief Reset the the object to an invalid state.
   */
  void reset();

  /**
   * @return True if the persistent bond is valid.
   */
  bool isValid() const;

  /**
   * @return The molecule the bond is a part of.
   */
  Molecule* molecule() const { return m_molecule; }

  /**
   * @brief The persistent unique ID of the bond.
   * @return The unique ID of the bond.
   */
  Index uniqueIdentifier() const { return m_uniqueId; }

  /**
   * @brief Obtain the bond being held by the persistent object.
   * @return A reference to the bond held by the object.
   */
  Core::Bond bond() const;

private:
  Molecule *m_molecule;
  Index m_uniqueId;
};

inline PersistentBond::PersistentBond(const Core::Bond &b)
  : m_molecule(dynamic_cast<QtGui::Molecule *>(b.molecule()))
{
  m_uniqueId = m_molecule ? m_molecule->bondUniqueId(b) : MaxIndex;
}

inline void PersistentBond::set(Molecule *m, Index uniqueId)
{
  m_molecule = m;
  m_uniqueId = uniqueId;
}

inline void PersistentBond::set(const Core::Bond &b)
{
  m_molecule = dynamic_cast<QtGui::Molecule *>(b.molecule());
  m_uniqueId = m_molecule ? m_molecule->bondUniqueId(b) : MaxIndex;
}

inline void PersistentBond::reset()
{
  set(NULL, MaxIndex);
}

inline bool PersistentBond::isValid() const
{
  return bond().isValid();
}

inline Core::Bond PersistentBond::bond() const
{
  return m_molecule ? m_molecule->bondByUniqueId(m_uniqueId) : Core::Bond();
}

} // End of QtGui namespace
} // End of Avogadro namespace

#endif // AVOGADRO_QTGUI_PERSISTENTBOND_H
