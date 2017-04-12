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

#ifndef AVOGADRO_CORE_SYMBOLATOMTYPER_H
#define AVOGADRO_CORE_SYMBOLATOMTYPER_H

#include "avogadrocore.h"

#include <avogadro/core/atomtyper.h>

#include <string>

namespace Avogadro {
namespace Core {

/**
 * @class SymbolAtomTyper symbolatomtyper.h <avogadro/core/symbolatomtyper.h>
 * @brief The SymbolAtomTyper class is a simple implementation of AtomTyper that
 * assigns element symbols to each atom.
 */
class AVOGADROCORE_EXPORT SymbolAtomTyper : public AtomTyper<std::string>
{
public:
  explicit SymbolAtomTyper(const Molecule* mol = nullptr);
  ~SymbolAtomTyper() override;

protected:
  std::string type(const Atom& atom) override;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_SYMBOLATOMTYPER_H
