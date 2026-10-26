/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CONTRASTCOLOR_H
#define AVOGADRO_CORE_CONTRASTCOLOR_H

#include <avogadro/core/vector.h>

#include <cmath>

namespace Avogadro::Core {

/**
 * @brief Relative luminance of an sRGB colour (WCAG 2).
 * @param rgb The colour, with 8-bit channels.
 * @return Luminance from 0 (black) to 1 (white), computed from the
 * linearised sRGB channels as 0.2126 R + 0.7152 G + 0.0722 B.
 */
inline double relativeLuminance(const Vector3ub& rgb)
{
  double linear[3];
  for (int i = 0; i < 3; ++i) {
    const double c = static_cast<double>(rgb[i]) / 255.0;
    linear[i] = c <= 0.04045 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
  }
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

/**
 * @brief WCAG 2 contrast ratio between two colours.
 * @return (L1 + 0.05) / (L2 + 0.05), with L1 the lighter luminance; always
 * between 1 (identical) and 21 (black on white).
 */
inline double contrastRatio(const Vector3ub& first, const Vector3ub& second)
{
  const double a = relativeLuminance(first);
  const double b = relativeLuminance(second);
  const double lighter = a > b ? a : b;
  const double darker = a > b ? b : a;
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * @brief Pick a legible text colour for a given background.
 * @return Pure black or pure white, whichever has the higher WCAG 2 contrast
 * ratio against @p rgb (at least 4.5:1 for every element colour).
 */
inline Vector3ub contrastColor(const Vector3ub& rgb)
{
  const Vector3ub black(0, 0, 0);
  const Vector3ub white(255, 255, 255);
  return contrastRatio(rgb, white) > contrastRatio(rgb, black) ? white : black;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_CONTRASTCOLOR_H
