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

#ifndef AVOGADRO_CORE_BOND_H
#define AVOGADRO_CORE_BOND_H

#include "avogadrocore.h"

#include <cstddef>

#include "atom.h"

namespace Avogadro {
namespace Core {

class Molecule;

/**
 * @class Bond bond.h <avogadro/core/bond.h>
 * @brief The Bond class represents a bond between two atoms in a molecule.
 */

class AVOGADROCORE_EXPORT Bond
{
public:
  /** Creates a new, invalid bond object. */
  Bond();

  /**
   * Creates a bond object representing a bond at index @p i in molecule @p m.
   */
  Bond(Molecule *m, size_t i);

  /** Returns \c true if the bond is valid. */
  bool isValid() const;

  /** Returns the molecule that the bond is a part of. */
  Molecule* molecule() const;

  /** Returns the index of the bond in the molecule. */
  size_t index() const;

  /** Returns the first atom in the molecule. */
  Atom atom1() const;

  /** Returns the second atom in the molecule. */
  Atom atom2() const;

  /**  Sets the bond order for the bond to @p order. */
  void setOrder(unsigned char o);

  /** Returns the bond order for the bond. */
  unsigned char order() const;

private:
  Molecule *m_molecule;
  size_t m_index;
};

inline bool operator==(const Bond& lhs, const Bond& rhs)
{
  if (lhs.molecule() == rhs.molecule() && lhs.index() == rhs.index())
    return true;
  else
    return false;
}

inline bool operator!=(const Bond& lhs, const Bond& rhs)
{
  return !operator==(lhs, rhs);
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_BOND_H
