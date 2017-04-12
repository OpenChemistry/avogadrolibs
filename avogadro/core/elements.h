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

/**
 * @class Elements elements.h <avogadro/core/elements.h>
 * @brief The Elements class stores basic data about chemical elements.
 *
 * The elements class gives a simple interface to basic data about chemical
 * elements. The data is automatically generated from the Blue Obelisk data
 * repository.
 *
 * The atomic numbers between the symbolic constants CustomElementMin and
 * CustomElementMax are used to represent non-elemental entities, such as
 * particles or structures units from MD simulations. Custom elements names and
 * symbols are returned as name="CustomElement_aa" and symbol="Xaa", where 'aa'
 * is some combination of lowercase letters that is unique to the particular
 * custom element atomic number. For all custom elements, the radii will match
 * Carbon, the color is random (but consistent), and the mass is zero.
 */

class AVOGADROCORE_EXPORT Elements
{
public:
  Elements();
  ~Elements();

  /** Get the number of elements in the database. */
  static unsigned char elementCount();

  /**
   * Get the atomic number from the supplied element name. If the name is not
   * recognised then Avogadro::InvalidElement will be returned. 0 represents the
   * dummy atom ("Dummy").
   * @note The input string is expected to be lowercase with the first letter
   * capitalized.
   */
  static unsigned char atomicNumberFromName(const std::string& name);

  /**
   * Get the atomic number from the supplied symbol. If the symbol is not
   * recognised then Avogadro::InvalidElement will be returned. 0 represents the
   * dummy atom ("Xx").
   * @note The input string is expected to be lowercase with the first letter
   * capitalized.
   */
  static unsigned char atomicNumberFromSymbol(const std::string& symbol);

  /**
   * Given a string, attempt to identify an element symbol, name, or atomic
   * number. This method is slower and less reliable than the
   * atomicNumberFrom*() methods, and is only intended for making an initial
   * guess of user input.
   * @return the atomic number that best matches the string, or InvalidElement
   * if no match can be made.
   */
  static unsigned char guessAtomicNumber(const std::string& str);

  /** Get the name of the element with the supplied atomic number. */
  static const char* name(unsigned char atomicNumber);

  /** Get the symbol of the element with the supplied atomic number. */
  static const char* symbol(unsigned char atomicNumber);

  /** Get the mass of the element with the supplied atomic number. */
  static double mass(unsigned char atomicNumber);

  /**
   * Get the Van der Waals radius of the element with the supplied atomic
   * number.
   */
  static double radiusVDW(unsigned char atomicNumber);

  /** Get the covalent radius of the element with the supplied atomic number. */
  static double radiusCovalent(unsigned char atomicNumber);

  /**
   * Get the default color of the element with the supplied atomic number.
   * This is a pointer to a static three component unsigned char color.
   */
  static const unsigned char* color(unsigned char atomicNumber);
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ELEMENTS_H
