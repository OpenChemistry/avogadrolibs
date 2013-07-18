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

#ifndef AVOGADRO_RENDERING_OVERLAYQUADSTRATEGY_H
#define AVOGADRO_RENDERING_OVERLAYQUADSTRATEGY_H

#include "quadplacementstrategy.h"
#include "avogadrorenderingexport.h"

#include "billboardquadstrategy.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class OverlayQuadStrategy overlayquadstrategy.h
 * <avogadro/rendering/overlayquadstrategy.h>
 * @brief The OverlayQuadStrategy class positions a resizable quad that
 * always faces a Camera, suitable for rendering during a overlay pass.
 *
 * The resulting quad is positioned using anchor(), hAlign(), and vAlign().
 * See the anchor() method for more information.
 */
class AVOGADRORENDERING_EXPORT OverlayQuadStrategy :
    public QuadPlacementStrategy
{
public:
  OverlayQuadStrategy();
  ~OverlayQuadStrategy() AVO_OVERRIDE;

  Core::Array<Vector3f> quad(const Camera &camera) AVO_OVERRIDE;

  /**
   * The point used to anchor the quad to the overlay plane. The units are
   * in fractions of the current view point, e.g. (0.0, 0.0) will anchor to the
   * bottom-left corner of the viewport, (1.0, 1.0) is the upper-right corner,
   * and (0.5, 0.5) is the center.
   */
  void setAnchor(const Vector2f &p) { m_anchor = p; }
  Vector2f anchor() const { return m_anchor; }
  /** @} */

  void setDimensions(const Vector2f &d) { m_strategy.setDimensions(d);}
  Vector2f dimensions() const { return m_strategy.dimensions(); }

  /**
   * The horizontal alignment of the quad to the anchor point.
   * @{
   */
  void setHAlign(HAlign align) { m_strategy.setHAlign(align); }
  HAlign hAlign() const { return m_strategy.hAlign(); }
  /** @} */

  /**
   * The vertical alignment of the quad to the anchor point.
   * @{
   */
  void setVAlign(VAlign align) { m_strategy.setVAlign(align); }
  VAlign vAlign() const { return m_strategy.vAlign(); }
  /** @} */

  /**
   * Set the horizontal and vertical alignment of the quad to the anchor point.
   */
  void setAlign(HAlign hAlign, VAlign vAlign);

private:
  BillboardQuadStrategy m_strategy;
  Vector2f m_anchor;
};

inline void OverlayQuadStrategy::setAlign(OverlayQuadStrategy::HAlign h,
                                          OverlayQuadStrategy::VAlign v)
{
  setHAlign(h);
  setVAlign(v);
}

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_OVERLAYQUADSTRATEGY_H
