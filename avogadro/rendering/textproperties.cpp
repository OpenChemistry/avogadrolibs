/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "textproperties.h"

#include <algorithm>

namespace Avogadro::Rendering {

TextProperties::TextProperties()
  : m_pixelHeight(24), m_hAlign(HLeft), m_vAlign(VTop),
    m_rotationDegreesCW(0.f), m_fontFamily(SansSerif), m_fontStyles(NoFontStyle)
{
  setColorRgba(255, 255, 255, 255);
}

TextProperties::TextProperties(const TextProperties& other)
  : m_pixelHeight(other.m_pixelHeight), m_hAlign(other.m_hAlign),
    m_vAlign(other.m_vAlign), m_rotationDegreesCW(other.m_rotationDegreesCW),
    m_fontFamily(other.m_fontFamily), m_fontStyles(other.m_fontStyles)
{
  m_rgba[0] = other.m_rgba[0];
  m_rgba[1] = other.m_rgba[1];
  m_rgba[2] = other.m_rgba[2];
  m_rgba[3] = other.m_rgba[3];
}

TextProperties::~TextProperties()
{
}

TextProperties& TextProperties::operator=(TextProperties other)
{
  swap(other);
  return *this;
}

void TextProperties::swap(TextProperties& other)
{
  using std::swap;
  swap(m_pixelHeight, other.m_pixelHeight);
  swap(m_hAlign, other.m_hAlign);
  swap(m_vAlign, other.m_vAlign);
  swap(m_rotationDegreesCW, other.m_rotationDegreesCW);
  swap(m_fontFamily, other.m_fontFamily);
  swap(m_fontStyles, other.m_fontStyles);
  swap(m_rgba[0], other.m_rgba[0]);
  swap(m_rgba[1], other.m_rgba[1]);
  swap(m_rgba[2], other.m_rgba[2]);
  swap(m_rgba[3], other.m_rgba[3]);
}

bool TextProperties::operator==(const TextProperties& other) const
{
  return m_pixelHeight == other.m_pixelHeight && m_hAlign == other.m_hAlign &&
         m_vAlign == other.m_vAlign &&
         m_rotationDegreesCW == other.m_rotationDegreesCW &&
         m_fontFamily == other.m_fontFamily &&
         m_fontStyles == other.m_fontStyles && m_rgba[0] == other.m_rgba[0] &&
         m_rgba[1] == other.m_rgba[1] && m_rgba[2] == other.m_rgba[2] &&
         m_rgba[3] == other.m_rgba[3];
}

} // namespace Avogadro
