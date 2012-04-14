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

#ifndef MOLCORE_BOND_H
#define MOLCORE_BOND_H

#include "molcore.h"

#include <cstddef>

#include "atom.h"

namespace MolCore {

class Molecule;

class MOLCORE_EXPORT Bond
{
public:
  // construction and destruction
  Bond();
  Bond(Molecule *m, size_t i);

  // properties
  bool isValid() const;
  Molecule* molecule() const;
  size_t index() const;
  Atom atom1() const;
  Atom atom2() const;
  void setOrder(unsigned char o);
  unsigned char order() const;

private:
  Molecule *m_molecule;
  size_t m_index;
};

} // end MolCore namespace

#endif // MOLCORE_BOND_H
