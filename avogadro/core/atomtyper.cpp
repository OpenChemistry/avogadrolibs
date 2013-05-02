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

#include "atomtyper.h"

#include "atom.h"
#include "molecule.h"

namespace Avogadro {
namespace Core {

AtomTyper::AtomTyper(const Molecule *mol)
  : m_molecule(mol)
{
}

AtomTyper::~AtomTyper()
{
}

void AtomTyper::setMolecule(const Molecule *mol)
{
  m_molecule = mol;
}

void AtomTyper::run()
{
  initialize();
  size_t numAtoms = m_molecule ? m_molecule->atomCount() : 0;
  for (size_t atomId = 0; atomId < numAtoms; ++atomId) {
    Atom atom = m_molecule->atom(atomId);
    m_types.push_back(type(atom));
  }
  finalize();
}

Array<std::string> AtomTyper::types() const
{
  return m_types;
}

void AtomTyper::initialize()
{
  m_types.clear();
  m_types.reserve(m_molecule ? m_molecule->atomCount() : 0);
}

void AtomTyper::finalize()
{
}

} // namespace Core
} // namespace Avogadro
