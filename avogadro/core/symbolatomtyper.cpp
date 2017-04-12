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

#include "symbolatomtyper.h"

#include "atom.h"
#include "elements.h"

namespace Avogadro {
namespace Core {

SymbolAtomTyper::SymbolAtomTyper(const Molecule* mol)
  : AtomTyper<std::string>(mol)
{
}

SymbolAtomTyper::~SymbolAtomTyper()
{
}

std::string SymbolAtomTyper::type(const Atom& atom)
{
  return std::string(Elements::symbol(atom.atomicNumber()));
}

} // namespace Core
} // namespace Avogadro
