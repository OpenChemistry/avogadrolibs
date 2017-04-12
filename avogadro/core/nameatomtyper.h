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

#ifndef AVOGADRO_CORE_NAMEATOMTYPER_H
#define AVOGADRO_CORE_NAMEATOMTYPER_H

#include "avogadrocore.h"

#include <avogadro/core/atomtyper.h>

#include <string>

namespace Avogadro {
namespace Core {

/**
 * @class NameAtomTyper nameatomtyper.h <avogadro/core/nameatomtyper.h>
 * @brief The NameAtomTyper class is a simple implementation of AtomTyper that
 * assigns element names to each atom.
 */
class AVOGADROCORE_EXPORT NameAtomTyper : public AtomTyper<std::string>
{
public:
  explicit NameAtomTyper(const Molecule* mol = nullptr);
  ~NameAtomTyper() override;

protected:
  std::string type(const Atom& atom) override;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_NAMEATOMTYPER_H
