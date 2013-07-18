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

#ifndef AVOGADRO_RENDERING_ABSOLUTEQUADSTRATEGY_H
#define AVOGADRO_RENDERING_ABSOLUTEQUADSTRATEGY_H

#include "quadplacementstrategy.h"
#include "avogadrorenderingexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class AbsoluteQuadStrategy absolutequadstrategy.h
 * <avogadro/rendering/absolutequadstrategy.h>
 * @brief QuadPlacementStrategy used to position a resizable quad at a fixed
 * position in object space.
 *
 * The resulting quad is positioned around anchor() using hAlign() and vAlign(),
 * facing normal(), with sides aligned to up().
 */
class AVOGADRORENDERING_EXPORT AbsoluteQuadStrategy
    : public QuadPlacementStrategy
{
public:
  AbsoluteQuadStrategy();
  ~AbsoluteQuadStrategy() AVO_OVERRIDE;

  Core::Array<Vector3f> quad(const Camera &) AVO_OVERRIDE;

  void setDimensions(const Vector2f &dims) AVO_OVERRIDE { m_dimensions = dims; }
  Vector2f dimensions() const AVO_OVERRIDE { return m_dimensions; }

  /**
   * The horizontal alignment of the quad to the anchor point.
   * @{
   */
  void setHAlign(HAlign align) { m_hAlign = align; }
  HAlign hAlign() const { return m_hAlign; }
  /** @} */

  /**
   * The vertical alignment of the quad to the anchor point.
   * @{
   */
  void setVAlign(VAlign align) { m_vAlign = align; }
  VAlign vAlign() const { return m_vAlign; }
  /** @} */

  /**
   * The vector pointing out of the quad. Must be normalized.
   * @{
   */
  void setNormal(const Vector3f &n) { m_normal = n; }
  Vector3f normal() const { return m_normal; }
  /** @} */

  /**
   * The vector pointing from the bottom to the top of the quad. Must be
   * normalized.
   * @{
   */
  void setUp(const Vector3f &u) { m_up = u; }
  Vector3f up() const { return m_up; }
  /** @} */

  /**
   * The point in 3D object space used to position the quad.
   * @sa hAlign
   * @sa vAlign
   * @{
   */
  void setAnchor(const Vector3f &p) { m_anchor = p; }
  Vector3f anchor() const { return m_anchor; }
  /** @} */

private:
  Vector2f m_dimensions;
  HAlign m_hAlign;
  VAlign m_vAlign;
  Vector3f m_anchor;
  Vector3f m_normal;
  Vector3f m_up;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_ABSOLUTEQUADSTRATEGY_H
