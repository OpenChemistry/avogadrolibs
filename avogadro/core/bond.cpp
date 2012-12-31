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

Bond::Bond()
  : m_molecule(0),
    m_index(size_t(-1))
{
}

Bond::Bond(Molecule *m, size_t i)
  : m_molecule(m),
    m_index(i)
{
}

bool Bond::isValid() const
{
  return m_molecule != 0;
}

Molecule* Bond::molecule() const
{
  return m_molecule;
}

size_t Bond::index() const
{
  return m_index;
}

Atom Bond::atom1() const
{
  if (m_molecule) {
    size_t atomIndex = m_molecule->bondPairs()[m_index].first;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

Atom Bond::atom2() const
{
  if (m_molecule) {
    size_t atomIndex = m_molecule->bondPairs()[m_index].second;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

void Bond::setOrder(unsigned char o)
{
  m_molecule->bondOrders()[m_index] = o;
}

unsigned char Bond::order() const
{
  return m_molecule->bondOrders()[m_index];
}

} // end Core namespace
} // end Avogadro namespace
