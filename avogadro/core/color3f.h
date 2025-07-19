/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_COLOR3F_H
#define AVOGADRO_CORE_COLOR3F_H

#include <array>

namespace Avogadro::Core {
namespace detail {
/** Used to represent Maximum RGB value as a float. */
constexpr float k_MaxRGBColorValue = 255.0f;
} // namespace detail

/**
 * @class Color3f color3f.h <avogadro/core/color3f.h>
 * @brief Representation of an RGB color using three floats.
 * @author Marcus D. Hanwell
 *
 * This class represents a color as three floats ranging from 0.0 to 1.0
 * specifying the intensity of the red, green and blue components of the
 * color. It is stored in memory as float[3], and so vectors containing this
 * type may be passed directly to OpenGL and other functions as C arrays.
 *
 * Several convenience functions are provided, the class is written with an
 * emphasis on efficiency and memory layout.
 */

class Color3f
{
public:
  /**
   * Constructor, results in a black Color3f object unless the RGB values are
   * set.
   * @param red Intensity (from 0.0 to 1.0) of the red component of the color.
   * @param green Intensity (from 0.0 to 1.0) of the green component of the
   * color.
   * @param blue Intensity (from 0.0 to 1.0) of the blue component of the color.
   */
  Color3f(float red = 0.0, float green = 0.0, float blue = 0.0);

  /**
   * Constructor where the color is constructed from integer values.
   * @param red Intensity (from 0 to 255) of the red component of the color.
   * @param green Intensity (from 0 to 255) of the green component of the color.
   * @param blue Intensity (from 0 to 255) of the blue component of the color.
   */
  Color3f(int red, int green, int blue);

  /**
   * Sets the color objects components.
   * @param red Intensity (from 0.0 to 1.0) of the red component of the color.
   * @param green Intensity (from 0.0 to 1.0) of the green component of the
   * color.
   * @param blue Intensity (from 0.0 to 1.0) of the blue component of the color.
   */
  void set(float red, float green, float blue);

  /**
   * @return The intensity of the red component of the color (0.0 to 1.0).
   */
  float red() const { return m_data[0]; }

  /**
   * @return The intensity of the green component of the color (0.0 to 1.0).
   */
  float green() const { return m_data[1]; }

  /**
   * @return The intensity of the blue component of the color (0.0 to 1.0).
   */
  float blue() const { return m_data[2]; }

  /**
   * @return Direct access to the underlying float array of size 3.
   */
  float* data();

  /**
   * This function is useful when calling OpenGL functions which expect a
   * float * array of size 3.
   * @return Direct access to the underlying float array of size 3.
   */
  const float* data() const;

protected:
  std::array<float, 3> m_data;
};

inline Color3f::Color3f(float r, float g, float b) : m_data({ r, g, b }) {}

// clang-format off
inline Color3f::Color3f(int r, int g, int b)
: m_data({static_cast<float>(r) / detail::k_MaxRGBColorValue,
          static_cast<float>(g) / detail::k_MaxRGBColorValue,
          static_cast<float>(b) / detail::k_MaxRGBColorValue})
{
}
// clang-format on

inline void Color3f::set(float r, float g, float b)
{
  m_data[0] = r;
  m_data[1] = g;
  m_data[2] = b;
}

inline float* Color3f::data()
{
  return m_data.data();
}

inline const float* Color3f::data() const
{
  return m_data.data();
}

} // End namespace Avogadro::Core

#endif // AVOGADRO_CORE_COLOR3F_H
