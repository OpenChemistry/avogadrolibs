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
 * @class GeometryVisitor geometryvisitor.h
 * <avogadro/rendering/geometryvisitor.h>
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
  ~GeometryVisitor() override;

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node&) override { return; }
  void visit(GroupNode&) override { return; }
  void visit(GeometryNode&) override { return; }
  void visit(Drawable&) override;
  void visit(SphereGeometry&) override;
  void visit(AmbientOcclusionSphereGeometry&) override;
  void visit(CurveGeometry&) override;
  void visit(CylinderGeometry&) override { return; }
  void visit(MeshGeometry&) override { return; }
  void visit(TextLabel2D&) override { return; }
  void visit(TextLabel3D&) override { return; }
  void visit(LineStripGeometry&) override;

  /**
   * Clear the state of the visitor.
   */
  void clear();

  /**
   * Get the position of the center of the scene.
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
