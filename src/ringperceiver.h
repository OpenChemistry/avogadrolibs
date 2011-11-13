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

#ifndef MOLCORE_RINGPERCEIVER_H
#define MOLCORE_RINGPERCEIVER_H

#include "molcore.h"

#include <vector>
#include <cstddef>

namespace MolCore {

class Molecule;

class MOLCORE_EXPORT RingPerceiver
{
public:
  // construction and destruction
  RingPerceiver(const Molecule *m = 0);
  ~RingPerceiver();

  // properties
  void setMolecule(const Molecule *m);
  const Molecule* molecule() const;

  // ring perception
  std::vector<std::vector<size_t> >& rings();

private:
  bool m_ringsPerceived;
  const Molecule *m_molecule;
  std::vector<std::vector<size_t> > m_rings;
};

} // end MolCore namespace

#endif // MOLCORE_RINGPERCEIVER_H
