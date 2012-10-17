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

#include "atom.h"

#include "molecule.h"

namespace Avogadro {
namespace Core {

// === Atom ================================================================ //
/// \class Atom
/// \brief The Atom class represents an atom in a molecule.

/// Creates a new, invalid atom object.
Atom::Atom()
  : m_molecule(0),
    m_index(size_t(-1))
{
}

/// Creates a new atom object representing the atom at index \p i in
/// molecule \p m.
Atom::Atom(Molecule *m, size_t i)
  : m_molecule(m),
    m_index(i)
{
}

/// Destroys the Atom object.
Atom::~Atom()
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

/// Sets the atom's 2d position to \p pos.
void Atom::setPosition2d(const Vector2 &pos)
{
  std::vector<Vector2> &positions = m_molecule->atomPositions2d();
  if (m_index >= positions.size())
    positions.resize(m_index + 1);
  positions[m_index] = pos;
}

/// Returns the atom's 2d position.
Vector2 Atom::position2d() const
{
  const std::vector<Vector2> &positions = m_molecule->atomPositions2d();
  if (m_index < positions.size())
    return positions[m_index];
  else
    return Vector2::Zero();
}

/// Sets the atom's 3d position to \p pos.
void Atom::setPosition3d(const Vector3 &pos)
{
  std::vector<Vector3> &positions = m_molecule->atomPositions3d();
  if (m_index >= positions.size())
    positions.resize(m_index + 1);
  positions[m_index] = pos;
}

/// Returns the atom's 3d position.
Vector3 Atom::position3d() const
{
  const std::vector<Vector3> &positions = m_molecule->atomPositions3d();
  if (m_index >= positions.size())
    return Vector3::Zero();
  else
    return positions[m_index];
}

} // end Core namespace
} // end Avogadro namespace
