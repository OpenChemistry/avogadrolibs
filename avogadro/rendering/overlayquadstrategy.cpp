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

#include "overlayquadstrategy.h"

#include "camera.h"

namespace Avogadro {
namespace Rendering {

OverlayQuadStrategy::OverlayQuadStrategy()
  : m_anchor(0, 0)
{
}

OverlayQuadStrategy::~OverlayQuadStrategy()
{
}

Core::Array<Vector3f>
OverlayQuadStrategy::quad(const Camera &camera)
{
  // Convert fractional anchor point into pixel coordinates:
  const Vector2i pixelCoords(
        static_cast<int>(std::floor(m_anchor.x() * camera.width())),
        static_cast<int>(std::floor(m_anchor.y() * camera.height())));
  m_strategy.setAnchor(pixelCoords);
  return m_strategy.quad(camera);
}

} // namespace Rendering
} // namespace Avogadro
