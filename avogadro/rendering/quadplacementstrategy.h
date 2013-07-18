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

#ifndef AVOGADRO_RENDERING_QUADPLACEMENTSTRATEGY_H
#define AVOGADRO_RENDERING_QUADPLACEMENTSTRATEGY_H

#include "avogadrorenderingexport.h"

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {
class Camera;

/**
 * @class QuadPlacementStrategy quadplacementstrategy.h
 * <avogadro/rendering/quadplacementstrategy.h>
 * @brief The QuadPlacementStrategy class defines an interface for generating
 * resizable rectangles that respond to camera movements.
 *
 * Subclasses of QuadPlacementStrategy implement methods for generating the
 * vertices of a quad in 3D space from, at a minimum, a camera and the
 * dimensions of the desired rectangle.
 */
class AVOGADRORENDERING_EXPORT QuadPlacementStrategy
{
public:
  /** Options for horizonal alignment. */
  enum HAlign { HLeft, HCenter, HRight };
  /** Options for vertical alignment. */
  enum VAlign { VTop, VCenter, VBottom };

  QuadPlacementStrategy();
  virtual ~QuadPlacementStrategy();

  /**
   * @param camera The current camera.
   * @return An array containing 4 vertices suitable for rendering as an OpenGL
   * triangle strip:
   * { top-left, top-right, bottom-left, bottom-right }
   */
  virtual Core::Array<Vector3f> quad(const Camera &camera) = 0;

  /**
   * The dimensions (width, height) of the rectangle returned by quad().
   * @{
   */
  virtual void setDimensions(const Vector2f &dims) = 0;
  virtual Vector2f dimensions() const = 0;
  /** @} */
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_QUADPLACEMENTSTRATEGY_H
