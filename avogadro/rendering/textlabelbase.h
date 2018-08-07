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

#ifndef AVOGADRO_RENDERING_TEXTLABELBASE_H
#define AVOGADRO_RENDERING_TEXTLABELBASE_H

#include "avogadrorenderingexport.h"
#include "drawable.h"

#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/array.h>

#include <string>

namespace Avogadro {
namespace Rendering {
class TextRenderStrategy;

/**
 * @class TextLabelBase textlabelbase.h <avogadro/rendering/textlabelbase.h>
 * @brief The TextLabelBase class provides a generic implementation of a text
 * drawable.
 */
class AVOGADRORENDERING_EXPORT TextLabelBase : public Drawable
{
public:
  TextLabelBase();
  TextLabelBase(const TextLabelBase& other);
  ~TextLabelBase() override;

  TextLabelBase& operator=(TextLabelBase other);
  friend void swap(TextLabelBase& lhs, TextLabelBase& rhs);

  void render(const Camera& camera) override;

  /**
   * Render the string to the internal texture buffer.
   * @param tren The text rendering strategy to use.
   */
  void buildTexture(const TextRenderStrategy& tren);

  /**
   * The text that will be rendered.
   * @{
   */
  void setText(const std::string& str);
  const std::string& text() const;
  /** @} */

  /**
   * The properties of the rendered text.
   * @{
   */
  void setTextProperties(const TextProperties& tprop);
  const TextProperties& textProperties() const;
  /** @} */

  /**
   * Clear the texture, forcing it to be regenerated on the next render.
   */
  void resetTexture();

protected:
  std::string m_text;
  TextProperties m_textProperties;
  Vector2i m_imageDimensions;
  Core::Array<unsigned char> m_imageRgba;

  // Subclasses use this to update the text position:
  void setAnchorInternal(const Vector3f& anchor);
  Vector3f getAnchorInternal() const;

  // ...and the radius.
  void setRadiusInternal(float radius);
  float getRadiusInternal() const;

  void markDirty();

private:
  // Container for rendering cache:
  class RenderImpl;
  RenderImpl* const m_render;
};

inline TextLabelBase& TextLabelBase::operator=(TextLabelBase other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(TextLabelBase& lhs, TextLabelBase& rhs)
{
  using std::swap;
  swap(static_cast<Drawable&>(lhs), static_cast<Drawable&>(rhs));
  swap(lhs.m_text, rhs.m_text);
  swap(lhs.m_textProperties, rhs.m_textProperties);
  swap(lhs.m_imageDimensions, rhs.m_imageDimensions);
  swap(lhs.m_imageRgba, rhs.m_imageRgba);
  lhs.markDirty();
  rhs.markDirty();
}

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABELBASE_H
