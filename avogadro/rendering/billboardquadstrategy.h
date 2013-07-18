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

#ifndef AVOGADRO_RENDERING_BILLBOARDQUADSTRATEGY_H
#define AVOGADRO_RENDERING_BILLBOARDQUADSTRATEGY_H

#include "quadplacementstrategy.h"
#include "avogadrorenderingexport.h"

#include "absolutequadstrategy.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class BillboardQuadStrategy billboardquadstrategy.h
 * <avogadro/rendering/billboardquadstrategy.h>
 * @brief The BillboardQuadStrategy class positions a resizable quad so that
 * it always faces a Camera.
 *
 * The resulting quad is positioned around anchor() using hAlign() and vAlign(),
 * facing the camera, with sides aligned to up(). Setting useCameraUp() will
 * ensure that the quad is always "right-side-up" with respect to the camera.
 */
class AVOGADRORENDERING_EXPORT BillboardQuadStrategy
    : public QuadPlacementStrategy
{
public:
  BillboardQuadStrategy();
  ~BillboardQuadStrategy() AVO_OVERRIDE;

  Core::Array<Vector3f> quad(const Camera &camera) AVO_OVERRIDE;

  /**
   * The point in 3D object space used to position the quad.
   * @sa hAlign
   * @sa vAlign
   * @{
   */
  void setAnchor(const Vector3f &p) { m_strategy.setAnchor(p); }
  Vector3f anchor() const { return m_strategy.anchor(); }
  /** @} */

  /**
   * If true, the quad will always be oriented to be "right-side-up" with
   * respect to the current Camera orientation. This will cause up() to be
   * overwritten with the last used up vector when quad() is called.
   * @{
   */
  void setUseCameraUp(bool b) { m_useCameraUp = b; }
  bool useCameraUp() const { return m_useCameraUp; }
  /** @} */

  /**
   * The vector pointing from the bottom to the top of the quad. Must be
   * normalized.
   * @{
   */
  void setUp(const Vector3f &p) { m_strategy.setUp(p); }
  Vector3f up() const { return m_strategy.up(); }
  /** @} */

  void setDimensions(const Vector2f &d) AVO_OVERRIDE
  {
    m_strategy.setDimensions(d);
  }
  Vector2f dimensions() const AVO_OVERRIDE
  {
    return m_strategy.dimensions();
  }

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

private:
  AbsoluteQuadStrategy m_strategy;
  bool m_useCameraUp;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_BILLBOARDQUADSTRATEGY_H
