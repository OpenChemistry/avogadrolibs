/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_RENDERING_TEXTPROPERTIES_H
#define AVOGADRO_RENDERING_TEXTPROPERTIES_H

#include "avogadrorenderingexport.h"

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class TextProperties textproperties.h <avogadro/rendering/textproperties.h>
 * @brief The TextProperties class controls formatting options for text.
 */
class AVOGADRORENDERING_EXPORT TextProperties
{
public:
  /** Enum defining a minimal set of font families. */
  enum FontFamily
  {
    SansSerif,
    Serif,
    Mono
  };

  /** Horizontal alignment options. */
  enum HAlign
  {
    HLeft,
    HCenter,
    HRight
  };

  /** Vertical alignment options. */
  enum VAlign
  {
    VTop,
    VCenter,
    VBottom
  };

  /** Flags for style options (bold, italic, ...) */
  enum FontStyle
  {
    NoFontStyle = 0x0,
    Bold = 0x1,
    Italic = 0x2,
    Underline = 0x4
  };

  /** Used for bitwise combinations of FontStyle values. */
  typedef int FontStyles;

  TextProperties();
  TextProperties(const TextProperties& other);
  ~TextProperties();

  TextProperties& operator=(TextProperties other);
  void swap(TextProperties& other);

  bool operator==(const TextProperties& other) const;
  bool operator!=(const TextProperties& other) const
  {
    return !operator==(other);
  }

  /**
   * The height of the text in pixels.
   */
  void setPixelHeight(size_t height) { m_pixelHeight = height; }
  size_t pixelHeight() const { return m_pixelHeight; }
  /** @} */

  /**
   * Horizontal alignment of the text.
   */
  void setHAlign(HAlign align) { m_hAlign = align; }
  HAlign hAlign() const { return m_hAlign; }
  /** @} */

  /**
   * Vertical alignment of the text.
   */
  void setVAlign(VAlign align) { m_vAlign = align; }
  VAlign vAlign() const { return m_vAlign; }
  /** @} */

  /**
   * Set the horizontal and vertical alignment of the quad to the anchor point.
   */
  void setAlign(HAlign hAlign, VAlign vAlign);

  /**
   * Rotates the text clockwise.
   */
  void setRotationDegreesCW(float rot) { m_rotationDegreesCW = rot; }
  float rotationDegreesCW() const { return m_rotationDegreesCW; }
  /** @} */

  /**
   * The font family.
   */
  void setFontFamily(FontFamily family) { m_fontFamily = family; }
  FontFamily fontFamily() const { return m_fontFamily; }
  /** @} */

  /**
   * Font style flags.
   */
  void setFontStyles(FontStyles styles) { m_fontStyles = styles; }
  FontStyles fontStyles() const { return m_fontStyles; }
  /** @} */

  /**
   * Toggle bold text.
   */
  void setBold(bool b);
  bool bold() const;
  /** @} */

  /**
   * Toggle italic text.
   */
  void setItalic(bool b);
  bool italic() const;
  /** @} */

  /**
   * Toggle underlined text.
   */
  void setUnderline(bool b);
  bool underline() const;
  /** @} */

  /**
   * Set the color of the text. Components are in the range [0, 255]
   * @{
   */
  void setColorRgba(unsigned char r, unsigned char g, unsigned char b,
                    unsigned char a);
  void setColorRgba(const unsigned char rgba[4]);
  void setColorRgba(const Vector4ub& rgba);
  void colorRgba(unsigned char rgba[4]) const;
  Vector4ub colorRgba() const;
  void setColorRgb(unsigned char r, unsigned char g, unsigned char b);
  void setColorRgb(const unsigned char rgb[3]);
  void setColorRgb(const Vector3ub& rgb);
  void colorRgb(unsigned char rgb[3]) const;
  Vector3ub colorRgb() const;
  void setRed(unsigned char r) { m_rgba[0] = r; }
  unsigned char red() const { return m_rgba[0]; }
  void setGreen(unsigned char g) { m_rgba[1] = g; }
  unsigned char green() const { return m_rgba[1]; }
  void setBlue(unsigned char b) { m_rgba[2] = b; }
  unsigned char blue() const { return m_rgba[2]; }
  void setAlpha(unsigned char a) { m_rgba[3] = a; }
  unsigned char alpha() const { return m_rgba[3]; }
  /** @} */

private:
  size_t m_pixelHeight;
  HAlign m_hAlign;
  VAlign m_vAlign;
  float m_rotationDegreesCW;
  FontFamily m_fontFamily;
  FontStyles m_fontStyles;
  unsigned char m_rgba[4];
};

inline void TextProperties::setAlign(TextProperties::HAlign h,
                                     TextProperties::VAlign v)
{
  setHAlign(h);
  setVAlign(v);
}

inline void TextProperties::setBold(bool b)
{
  if (b)
    m_fontStyles |= Bold;
  else
    m_fontStyles &= ~Bold;
}

inline bool TextProperties::bold() const
{
  return (m_fontStyles & Bold) != 0;
}

inline void TextProperties::setItalic(bool b)
{
  if (b)
    m_fontStyles |= Italic;
  else
    m_fontStyles &= ~Italic;
}

inline bool TextProperties::italic() const
{
  return (m_fontStyles & Italic) != 0;
}

inline void TextProperties::setUnderline(bool b)
{
  if (b)
    m_fontStyles |= Underline;
  else
    m_fontStyles &= ~Underline;
}

inline bool TextProperties::underline() const
{
  return (m_fontStyles & Underline) != 0;
}

inline void TextProperties::setColorRgba(unsigned char r, unsigned char g,
                                         unsigned char b, unsigned char a)
{
  m_rgba[0] = r;
  m_rgba[1] = g;
  m_rgba[2] = b;
  m_rgba[3] = a;
}

inline void TextProperties::setColorRgba(const unsigned char rgba[4])
{
  m_rgba[0] = rgba[0];
  m_rgba[1] = rgba[1];
  m_rgba[2] = rgba[2];
  m_rgba[3] = rgba[3];
}

inline void TextProperties::setColorRgba(const Vector4ub& rgba)
{
  setColorRgba(rgba.data());
}

inline void TextProperties::colorRgba(unsigned char rgba[4]) const
{
  rgba[0] = m_rgba[0];
  rgba[1] = m_rgba[1];
  rgba[2] = m_rgba[2];
  rgba[3] = m_rgba[3];
}

inline Vector4ub TextProperties::colorRgba() const
{
  return Vector4ub(m_rgba);
}

inline void TextProperties::setColorRgb(unsigned char r, unsigned char g,
                                        unsigned char b)
{
  m_rgba[0] = r;
  m_rgba[1] = g;
  m_rgba[2] = b;
}

inline void TextProperties::setColorRgb(const unsigned char rgb[3])
{
  m_rgba[0] = rgb[0];
  m_rgba[1] = rgb[1];
  m_rgba[2] = rgb[2];
}

inline void TextProperties::setColorRgb(const Vector3ub& rgb)
{
  setColorRgb(rgb.data());
}

inline void TextProperties::colorRgb(unsigned char rgb[3]) const
{
  rgb[0] = m_rgba[0];
  rgb[1] = m_rgba[1];
  rgb[2] = m_rgba[2];
}

inline Vector3ub TextProperties::colorRgb() const
{
  return Vector3ub(m_rgba);
}

inline void swap(TextProperties& lhs, TextProperties& rhs)
{
  lhs.swap(rhs);
}

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTPROPERTIES_H
