/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_ELEMENTS_H
#define AVOGADRO_CORE_ELEMENTS_H

#include "avogadrocore.h"

#include <string>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT Elements
{
public:
  Elements();
  virtual ~Elements();

  /** Get the atomic number from the supplied symbol. If the symbol is not
   * recognised then 0 will be returned. 0 is also the dummy atom. */
  static unsigned char atomicNumberFromSymbol(const std::string &symbol);

  /** Get the name of the element with the supplied atomic number. */
  static const char * name(unsigned char atomicNumber);

  /** Get the symbol of the element with the supplied atomic number. */
  static const char * symbol(unsigned char atomicNumber);

  /** Get the mass of the element with the supplied atomic number. */
  static double mass(unsigned char atomicNumber);

  /** Get the Van der Waals radius of the element with the supplied atomic
   * number. */
  static double radiusVDW(unsigned char atomicNumber);

  /** Get the covalent radius of the element with the supplied atomic number. */
  static double radiusCovalent(unsigned char atomicNumber);

  /** Get the default color of the element with the supplied atomic number.
   * This is a pointer to a static three component unsigned char color. */
  static const unsigned char * color(unsigned char atomicNumber);
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ELEMENTS_H
