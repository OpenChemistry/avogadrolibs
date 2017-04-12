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

#ifndef AVOGADRO_RENDERING_TEXTLABEL3D_H
#define AVOGADRO_RENDERING_TEXTLABEL3D_H

#include "avogadrorenderingexport.h"
#include "textlabelbase.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class TextLabel3D textlabel3d.h <avogadro/rendering/textlabel3d.h>
 * @brief The TextLabel3D class renders billboarded text that is anchored to a
 * point in world coordinates.
 */
class AVOGADRORENDERING_EXPORT TextLabel3D : public TextLabelBase
{
public:
  TextLabel3D();
  ~TextLabel3D() override;

  void accept(Visitor&) override;

  /**
   * The anchor position in world coordinates.
   * @{
   */
  void setAnchor(const Vector3f& position);
  Vector3f anchor() const;
  /** @} */

  /**
   * The distance to project the label towards the camera from the anchor point.
   * Useful for moving the label on top of, e.g. atom spheres. 0.f by default.
   * @{
   */
  void setRadius(float r);
  float radius() const;
  /** @} */
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABEL3D_H
