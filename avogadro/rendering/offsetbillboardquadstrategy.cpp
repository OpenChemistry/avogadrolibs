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

#include "offsetbillboardquadstrategy.h"

#include "camera.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

OffsetBillboardQuadStrategy::OffsetBillboardQuadStrategy()
  : m_anchor(0.f, 0.f, 0.f),
    m_radius(1.f)
{
}

OffsetBillboardQuadStrategy::~OffsetBillboardQuadStrategy()
{
}

Core::Array<Vector3f> OffsetBillboardQuadStrategy::quad(const Camera &camera)
{
  const Matrix3f basis(camera.modelView().linear().transpose());
  const Vector3f normal(basis.col(2).normalized());
  m_strategy.setAnchor(m_anchor + (normal * m_radius));
  return m_strategy.quad(camera);
}

} // namespace Rendering
} // namespace Avogadro
