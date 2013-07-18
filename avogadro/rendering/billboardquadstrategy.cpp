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
  : m_useCameraUp(true)
{
}

BillboardQuadStrategy::~BillboardQuadStrategy()
{
}

Core::Array<Vector3f> BillboardQuadStrategy::quad(const Camera &camera)
{
  const Matrix3f basis(camera.modelView().linear().transpose());
  m_strategy.setNormal(basis.col(2).normalized());
  if (m_useCameraUp)
    m_strategy.setUp(basis.col(1).normalized());
  return m_strategy.quad(camera);
}

} // namespace Rendering
} // namespace Avogadro
