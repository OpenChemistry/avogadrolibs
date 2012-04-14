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

#ifndef AVOGADRO_CORE_ATOM_H
#define AVOGADRO_CORE_ATOM_H

#include "avogadrocore.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

class Molecule;

class AVOGADROCORE_EXPORT Atom
{
public:
  // construction and destruction
  Atom();
  Atom(Molecule *m, size_t i);

  // properties
  bool isValid() const;
  Molecule* molecule() const;
  size_t index() const;
  void setAtomicNumber(unsigned char number);
  unsigned char atomicNumber() const;

  void setPosition2d(const Vector2 &pos);
  Vector2 position2d() const;
  void setPosition3d(const Vector3 &pos);
  Vector3 position3d() const;

private:
  Molecule *m_molecule;
  size_t m_index;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ATOM_H
