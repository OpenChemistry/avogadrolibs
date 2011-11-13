/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "atom.h"

#include "molecule.h"

namespace MolCore {

// === Atom ================================================================ //
/// \class Atom
/// \brief The Atom class represents an atom in a molecule.

/// Creates a new, invalid atom object.
Atom::Atom()
  : m_molecule(0),
    m_index(-1)
{
}

/// Creates a new atom object representing the atom at index \p i in
/// molecule \p m.
Atom::Atom(Molecule *m, size_t i)
  : m_molecule(m),
    m_index(i)
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns \c true if the atom is valid.
bool Atom::isValid() const
{
  return m_molecule != 0;
}

/// Returns the molecule the atom is a part of.
Molecule* Atom::molecule() const
{
  return m_molecule;
}

/// Returns the atom's index in the molecule.
size_t Atom::index() const
{
  return m_index;
}

/// Sets the atom's atomic number to \p number.
void Atom::setAtomicNumber(unsigned char number)
{
  m_molecule->atomicNumbers()[m_index] = number;
}

/// Returns the atom's atomic number.
unsigned char Atom::atomicNumber() const
{
  return m_molecule->atomicNumbers()[m_index];
}

} // end MolCore namespace
