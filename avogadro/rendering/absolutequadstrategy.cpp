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

#include "absolutequadstrategy.h"

#include <Eigen/Geometry>

#include <iostream>

namespace Avogadro {
namespace Rendering {

AbsoluteQuadStrategy::AbsoluteQuadStrategy()
  : m_dimensions(0, 0),
    m_hAlign(HLeft),
    m_vAlign(VTop),
    m_anchor(0, 0, 0),
    m_normal(0, 0, 1),
    m_up(0, 1, 0)
{
}

AbsoluteQuadStrategy::~AbsoluteQuadStrategy()
{
}

Core::Array<Vector3f> AbsoluteQuadStrategy::quad(const Camera &)
{
  // a la triangle strip: tl, tr, bl, br
  Core::Array<Vector3f> result(4);
  Vector3f &tl = result[0];
  Vector3f &tr = result[1];
  Vector3f &bl = result[2];
  Vector3f &br = result[3];

  // If the up vector is not orthogonal to the normal, use the vector
  // rejection of up onto m_normal (ie. the projection of up onto the plane
  // orthogonal to m_normal):
  Vector3f safeUp(m_up);
  if (!m_normal.isOrthogonal(safeUp, 1e-5))
    safeUp = (safeUp - (safeUp.dot(m_normal) * m_normal)).normalized();

  // Generate vectors that point along the edges of the quad
  Vector3f leftRight(safeUp.cross(m_normal));
  Vector3f bottomTop(safeUp);

  // Adjust for length
  leftRight *= m_dimensions.x();
  bottomTop *= m_dimensions.y();

  // Determine top left corner:
  tl = m_anchor;
  switch (m_hAlign) {
  default:
    std::cerr << "Avogadro::Rendering::AbsoluteQuadStrategy::quad error: "
                 "Unrecognized horizontal alignment (" << m_hAlign << "). "
                 "Assuming HLeft." << std::endl;
  case HLeft:
    break;
  case HCenter:
    tl -= leftRight * 0.5;
    break;
  case HRight:
    tl -= leftRight;
    break;
  }

  switch (m_vAlign) {
  default:
    std::cerr << "Avogadro::Rendering::AbsoluteQuadStrategy::quad error: "
                 "Unrecognized vertical alignment (" << m_vAlign << "). "
                 "Assuming VTop." << std::endl;
  case VTop:
    break;
  case VCenter:
    tl += bottomTop * 0.5;
    break;
  case VBottom:
    tl += bottomTop;
    break;
  }

  // Complete the quad
  tr = tl + leftRight;
  bl = tl - bottomTop;
  br = tr - bottomTop;

  return result;
}

} // namespace Rendering
} // namespace Avogadro
