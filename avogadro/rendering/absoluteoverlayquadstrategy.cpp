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

#include "absoluteoverlayquadstrategy.h"

namespace Avogadro {
namespace Rendering {

AbsoluteOverlayQuadStrategy::AbsoluteOverlayQuadStrategy()
{
}

AbsoluteOverlayQuadStrategy::~AbsoluteOverlayQuadStrategy()
{

}

Core::Array<Vector3f> AbsoluteOverlayQuadStrategy::quad(const Camera &camera)
{
  // Convert to 3D coordinate
  const Vector3f pixelCoords(static_cast<float>(m_anchor.x()),
                             static_cast<float>(m_anchor.y()),
                             0.f);
  m_strategy.setAnchor(pixelCoords);
  return m_strategy.quad(camera);

}

} // namespace Rendering
} // namespace Avogadro
