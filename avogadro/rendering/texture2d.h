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

#ifndef AVOGADRO_RENDERING_TEXTURE2D_H
#define AVOGADRO_RENDERING_TEXTURE2D_H

#include "drawable.h"

#include <avogadro/core/array.h>

namespace Avogadro {
namespace Rendering {
class QuadPlacementStrategy;

/**
 * @class Texture2D texture2d.h <avogadro/rendering/texture2d.h>
 * @brief The Texture2D class renders a 2D texture to a quad.
 */
class AVOGADRORENDERING_EXPORT Texture2D : public Drawable
{
public:
  Texture2D();
  ~Texture2D();

  void accept(Visitor &) AVO_OVERRIDE;

  /**
   * Render the texture.
   */
  void render(const Camera &camera);

  /**
   * The texture data. The data must be in RGBA32 format with the top scan
   * row at the beginning of the data. The dimensions are specified in pixels.
   * @{
   */
  void setTextureData(const Core::Array<unsigned char> &data,
                      size_t width, size_t height);
  Core::Array<unsigned char> textureData() const;
  void textureSize(size_t size[2]) const;
  /** @} */

  /**
   * The method used to generate the quad coordinates. When setting a placement
   * strategy, this class takes ownership of the strategy object.
   * @sa AbsoluteQuadStrategy
   * @sa BillboardQuadStrategy
   * @sa OverlayBillboardStrategy
   * @{
   */
  void setQuadPlacementStrategy(QuadPlacementStrategy *strategy);
  const QuadPlacementStrategy* quadPlacementStrategy() const;
  QuadPlacementStrategy* quadPlacementStrategy();
  /** @} */

  /**
   * @brief An array of 4 texture coordinates mapping suitable for rendering
   * a 4 vertex OpenGL triangle script:
   * { top-left, top-right, bottom-left, bottom-right }
   * @{
   */
  void setTextureCoordinates(const Core::Array<Vector2f> tcoords);
  Core::Array<Vector2f> textureCoordinates() const;
  /** @} */

protected:
  QuadPlacementStrategy *m_quadPlacementStrategy;
  bool m_textureSynced;
  size_t m_textureSize[2];
  Core::Array<unsigned char> m_textureData;
  Core::Array<Vector2f> m_textureCoordinates;

private:
  bool prepareGl(const Camera &camera);

private:
  // Use to separate code/vars used in the render() method that should be moved
  // into another module eventually.
  class Private;
  Private *d;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTURE2D_H
