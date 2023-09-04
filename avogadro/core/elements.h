/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ELEMENTS_H
#define AVOGADRO_CORE_ELEMENTS_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <string>

namespace Avogadro {
namespace Core {

const unsigned char element_count = 119; //!< from 0 to 118

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

  /** @return the number of elements in the database. */
  static unsigned char elementCount();

  /**
   * @return the atomic number from the supplied element @p name. If the name is
   * not recognised then Avogadro::InvalidElement will be returned. 0 represents
   * the dummy atom ("Dummy").
   * @note The input string is expected to be lowercase with the first letter
   * capitalized.
   */
  static unsigned char atomicNumberFromName(const std::string& name);

  /**
   * @return the atomic number from the supplied @p symbol. If the symbol is not
   * recognised then Avogadro::InvalidElement will be returned. 0 represents the
   * dummy atom ("Xx").
   * @note The input string is expected to be lowercase with the first letter
   * capitalized.
   */
  static unsigned char atomicNumberFromSymbol(const std::string& symbol);

  /**
   * Given a string @p str, attempt to identify an element symbol, name, or
   * atomic number. This method is slower and less reliable than the
   * atomicNumberFrom*() methods, and is only intended for making an initial
   * guess of user input.
   * @return the atomic number that best matches the string, or InvalidElement
   * if no match can be made.
   */
  static unsigned char guessAtomicNumber(const std::string& str);

  /** @return the name of the element with the supplied @p atomicNumber. */
  static const char* name(unsigned char atomicNumber);

  /** @return the symbol of the element with the supplied @p atomicNumber. */
  static const char* symbol(unsigned char atomicNumber);

  /** @return the mass of the element with the supplied @p atomicNumber. */
  static double mass(unsigned char atomicNumber);

  /**
   * @return the Van der Waals radius of the element with the supplied
   * @p atomicNumber.
   */
  static double radiusVDW(unsigned char atomicNumber);

  /** @return the covalent radius of the element with the supplied
   * @p atomicNumber.
   */
  static double radiusCovalent(unsigned char atomicNumber);

  /**
   * @return the default color of the element with the supplied @p atomicNumber.
   * This is a pointer to a static three component unsigned char color.
   */
  static const unsigned char* color(unsigned char atomicNumber);

  /** @return the number of valence electrons for the supplied @p atomicNumber
   */
  static unsigned char valenceElectrons(unsigned char atomicNumber);
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ELEMENTS_H
