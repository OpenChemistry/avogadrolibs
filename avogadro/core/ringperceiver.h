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

#ifndef AVOGADRO_CORE_RINGPERCEIVER_H
#define AVOGADRO_CORE_RINGPERCEIVER_H

#include "avogadrocore.h"

#include <cstddef>
#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;

class AVOGADROCORE_EXPORT RingPerceiver
{
public:
  // construction and destruction
  explicit RingPerceiver(const Molecule* m = nullptr);
  ~RingPerceiver();

  // properties
  void setMolecule(const Molecule* m);
  const Molecule* molecule() const;

  // ring perception
  std::vector<std::vector<size_t>>& rings();

private:
  bool m_ringsPerceived;
  const Molecule* m_molecule;
  std::vector<std::vector<size_t>> m_rings;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_RINGPERCEIVER_H
