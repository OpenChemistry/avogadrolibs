 /******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_H
#define AVOGADRO_CORE_H

#include <cstddef>
#include <limits>

/**
 * This macro marks a parameter as unused. Its purpose is to disable the
 * compiler from emitting unused parameter warnings.
 */
#define AVO_UNUSED(variable) (void)variable

namespace Avogadro {

/** Typedef for a real number. */
using Real = double;

/** Typedef for indices and sizes. */
using Index = std::size_t;
constexpr Index MaxIndex = std::numeric_limits<Index>::max();

/** Used to represent an invalid atomic number. */
constexpr unsigned char InvalidElement = 255;

/**
 * Minimum value for atomic numbers that represent custom, non-elemental
 * particles.
 */
constexpr unsigned char CustomElementMin = 128;

/**
 * Maximum value for atomic numbers that represent custom, non-elemental
 * particles.
 */
constexpr unsigned char CustomElementMax = 254;

/**
 * Count of atomic number values that are used to represent custom,
 * non-elemental particles.
 */
constexpr unsigned char CustomElementCount =
    CustomElementMax - CustomElementMin + 1;

/**
 * @return True if @a atomicNumber denotes a custom element type.
 */
namespace Core {
constexpr bool isCustomElement(unsigned char atomicNumber) {
    return atomicNumber >= CustomElementMin && atomicNumber <= CustomElementMax;
}
}

/** Unit conversion factors. @{ */
constexpr double PI_D = 3.141592653589793238462643;
constexpr float PI_F = static_cast<float>(PI_D);
constexpr Real PI = static_cast<Real>(PI_D);

constexpr double DEG_TO_RAD_D = PI_D / 180.0;
constexpr float DEG_TO_RAD_F = static_cast<float>(DEG_TO_RAD_D);
constexpr Real DEG_TO_RAD = static_cast<Real>(DEG_TO_RAD_D);

constexpr double RAD_TO_DEG_D = 180.0 / PI_D;
constexpr float RAD_TO_DEG_F = static_cast<float>(RAD_TO_DEG_D);
constexpr Real RAD_TO_DEG = static_cast<Real>(RAD_TO_DEG_D);

constexpr double BOHR_TO_ANGSTROM_D = 0.52917721092;
constexpr float BOHR_TO_ANGSTROM_F = static_cast<float>(BOHR_TO_ANGSTROM_D);
constexpr Real BOHR_TO_ANGSTROM = static_cast<Real>(BOHR_TO_ANGSTROM_D);

constexpr double ANGSTROM_TO_BOHR_D = 1.0 / BOHR_TO_ANGSTROM_D;
constexpr float ANGSTROM_TO_BOHR_F = static_cast<float>(ANGSTROM_TO_BOHR_D);
constexpr Real ANGSTROM_TO_BOHR = static_cast<Real>(ANGSTROM_TO_BOHR_D);
/** @} */

} // end Avogadro namespace

#endif // AVOGADRO_CORE_H
