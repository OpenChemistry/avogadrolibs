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

class Molecule;

/**
 * @class Atom atom.h <avogadro/core/atom.h>
 * @brief The Atom class represents an atom in a molecule.
 */

class AVOGADROCORE_EXPORT Atom
{
public:
  /** Creates a new, invalid atom object. */
  Atom();

  /**
   * Creates a new atom object representing the atom at index @p i in molecule
   * @p m.
   */
  Atom(Molecule *m, Index i);

  /** Returns \c true if the atom is valid. */
  bool isValid() const;

  /** Returns the molecule the atom is a part of. */
  Molecule* molecule() const;

  /** Returns the atom's index in the molecule. */
  Index index() const;

  /** Sets the atom's atomic number to @p number. */
  void setAtomicNumber(unsigned char number);

  /** Returns the atom's atomic number. */
  unsigned char atomicNumber() const;

  /** Sets the atom's 2d position to @p pos. */
  void setPosition2d(const Vector2 &pos);

  /** Returns the atom's 2d position. */
  Vector2 position2d() const;

  /** Sets the atom's 3d position to @p pos. */
  void setPosition3d(const Vector3 &pos);

  /** Returns the atom's 3d position. */
  Vector3 position3d() const;

private:
  Molecule *m_molecule;
  Index m_index;
};

inline bool operator==(const Atom& lhs, const Atom& rhs)
{
  if (lhs.molecule() == rhs.molecule() && lhs.index() == rhs.index())
    return true;
  else
    return false;
}

inline bool operator!=(const Atom& lhs, const Atom& rhs)
{
  return !operator==(lhs, rhs);
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ATOM_H
