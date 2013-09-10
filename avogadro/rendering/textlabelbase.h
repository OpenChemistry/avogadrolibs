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

#include "drawable.h"
#include "avogadrorenderingexport.h"

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
  ~TextLabelBase();

  void render(const Camera &camera) AVO_OVERRIDE;

  /**
   * Render the string to the internal texture buffer.
   * @param tren The text rendering strategy to use.
   */
  void buildTexture(const TextRenderStrategy &tren);

  /**
   * The text that will be rendered.
   * @{
   */
  void setText(const std::string &str);
  const std::string & text() const;
  /** @} */

  /**
   * The properties of the rendered text.
   * @{
   */
  void setTextProperties(const TextProperties &tprop);
  const TextProperties & textProperties() const;
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
  void setAnchorInternal(const Vector3f &anchor);
  Vector3f getAnchorInternal() const;

  // ...and the radius.
  void setRadiusInternal(float radius);
  float getRadiusInternal() const;

private:
  // Container for rendering cache:
  class RenderImpl;
  RenderImpl * const m_render;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABELBASE_H
