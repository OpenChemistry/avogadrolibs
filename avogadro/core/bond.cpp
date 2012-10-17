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

#include "bond.h"

#include "molecule.h"

namespace Avogadro {
namespace Core {

// === Bond ================================================================ //
/// \class Bond
/// \brief The Bond class represents a bond between two atoms in a
///        molecule.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new, invalid bond object.
Bond::Bond()
  : m_molecule(0),
    m_index(size_t(-1))
{
}

/// Creates a bond object representing a bond at index \p i in
/// molecule \p m.
Bond::Bond(Molecule *m, size_t i)
  : m_molecule(m),
    m_index(i)
{
}

/// Destroys the Bond object.
Bond::~Bond()
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns \c true if the bond is valid.
bool Bond::isValid() const
{
  return m_molecule != 0;
}

/// Returns the molecule that the bond is a part of.
Molecule* Bond::molecule() const
{
  return m_molecule;
}

/// Returns the index of the bond in the molecule.
size_t Bond::index() const
{
  return m_index;
}

/// Returns the first atom in the molecule.
Atom Bond::atom1() const
{
  if (m_molecule) {
    size_t atomIndex = m_molecule->bondPairs()[m_index].first;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

/// Returns the second atom in the molecule.
Atom Bond::atom2() const
{
  if (m_molecule) {
    size_t atomIndex = m_molecule->bondPairs()[m_index].second;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

/// Sets the bond order for the bond to \p order.
void Bond::setOrder(unsigned char o)
{
  m_molecule->bondOrders()[m_index] = o;
}

/// Returns the bond order for the bond.
unsigned char Bond::order() const
{
  return m_molecule->bondOrders()[m_index];
}

} // end Core namespace
} // end Avogadro namespace
