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

#include <vector>

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
  void visit(AmbientOcclusionSphereGeometry &) AVO_OVERRIDE;
  void visit(CylinderGeometry &) AVO_OVERRIDE { return; }
  void visit(MeshGeometry &) AVO_OVERRIDE { return; }
  void visit(TextLabel2D &) AVO_OVERRIDE { return; }
  void visit(TextLabel3D &) AVO_OVERRIDE { return; }
  void visit(LineStripGeometry &) AVO_OVERRIDE;

  /**
   * Clear the state of the visitor.
   */
  void clear();

  /**
   * Get the positiion of the center of the scene.
   */
  Vector3f center();

  /**
   * Get the radius of the scene.
   */
  float radius();

private:
  /**
   * Get the average of the accumulated spherical centers and minimal radius.
   */
  void average();

  Vector3f m_center;
  float m_radius;
  bool m_dirty;

  std::vector<Vector3f> m_centers;
  std::vector<float> m_radii;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYVISITOR_H
