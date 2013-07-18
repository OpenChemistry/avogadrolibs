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

#include "billboardquadstrategy.h"

#include "camera.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

BillboardQuadStrategy::BillboardQuadStrategy()
  : m_useCameraUp(true),
    m_anchor(0.f, 0.f, 0.f),
    m_radius(0.f)
{
}

BillboardQuadStrategy::~BillboardQuadStrategy()
{
}

Core::Array<Vector3f> BillboardQuadStrategy::quad(const Camera &camera)
{
  const Matrix3f basis(camera.modelView().linear().transpose());
  const Vector3f normal(basis.col(2).normalized());
  m_strategy.setNormal(normal);
  m_strategy.setAnchor(m_anchor + (normal * m_radius));
  if (m_useCameraUp)
    m_strategy.setUp(basis.col(1).normalized());
  return m_strategy.quad(camera);
}

} // namespace Rendering
} // namespace Avogadro
