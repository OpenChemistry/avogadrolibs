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

#ifndef AVOGADRO_RENDERING_GEOMETRYVISITOR_H
#define AVOGADRO_RENDERING_GEOMETRYVISITOR_H

#include "visitor.h"

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class GeometryVisitor geometryvisitor.h <avogadro/rendering/geometryvisitor.h>
 * @brief Visitor that determines the geometry of the scene.
 * @author Marcus D. Hanwell
 *
 * This visitor will attempt to determine the geometry of the scene, most
 * notably the center and radius of the bounding sphere.
 */

class GeometryVisitor : public Visitor
{
public:
  GeometryVisitor();
  ~GeometryVisitor() AVO_OVERRIDE;

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node &) AVO_OVERRIDE { return; }
  void visit(GroupNode &) AVO_OVERRIDE { return; }
  void visit(GeometryNode &) AVO_OVERRIDE { return; }
  void visit(Drawable &) AVO_OVERRIDE;
  void visit(SphereGeometry &) AVO_OVERRIDE;

  /**
   * Get the positiion of the center of the scene.
   */
  Vector3f center() const { return m_center; }

  /**
   * Get the radius of the scene.
   */
  float radius() const { return m_radius; }

private:
  Vector3f m_center;
  float m_radius;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYVISITOR_H
