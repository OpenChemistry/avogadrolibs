/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CONTRASTCOLOR_H
#define AVOGADRO_CORE_CONTRASTCOLOR_H

#include <avogadro/core/vector.h>

#include <cmath>

namespace Avogadro::Core {

inline Vector3ub contrastColor(const Vector3ub& rgb)
{
  // If we're far 'enough' (+/-32) away from 128, just invert the component.
  // If we're close to 128, inverting the color will end up too close to the
  // input -- adjust the component before inverting.
  const unsigned char minVal = 32;
  const unsigned char maxVal = 223;
  Vector3ub result;
  for (size_t i = 0; i < 3; ++i) {
    unsigned char input = rgb[i];
    if (input > 160 || input < 96)
      result[i] = static_cast<unsigned char>(255 - input);
    else
      result[i] = static_cast<unsigned char>(255 - (input / 4));

    // Clamp to 32-->223 to prevent pure black/white
    result[i] = std::clamp(result[i], minVal, maxVal);
  }

  return result;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_CONTRASTCOLOR_H
