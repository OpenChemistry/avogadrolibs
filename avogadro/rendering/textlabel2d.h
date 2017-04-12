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

#ifndef AVOGADRO_RENDERING_TEXTLABEL2D_H
#define AVOGADRO_RENDERING_TEXTLABEL2D_H

#include "avogadrorenderingexport.h"
#include "textlabelbase.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class TextLabel2D textlabel2d.h <avogadro/rendering/textlabel2d.h>
 * @brief The TextLabel2D class renders text in an overlay plane, anchored to
 * a point in window coordinates.
 */
class AVOGADRORENDERING_EXPORT TextLabel2D : public TextLabelBase
{
public:
  TextLabel2D();
  ~TextLabel2D() override;

  void accept(Visitor&) override;

  /**
   * The anchor point in window coordinates, taking the origin at the upper-left
   * corner.
   * @{
   */
  void setAnchor(const Vector2i& windowCoords);
  Vector2i anchor() const;
  /** @} */
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABEL2D_H
