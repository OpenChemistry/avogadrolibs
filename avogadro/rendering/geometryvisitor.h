/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GEOMETRYVISITOR_H
#define AVOGADRO_RENDERING_GEOMETRYVISITOR_H

#include "avogadrorenderingexport.h"
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

class AVOGADRORENDERING_EXPORT GeometryVisitor : public Visitor
{
public:
  GeometryVisitor();
  ~GeometryVisitor() override;

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node&) override {}
  void visit(GroupNode&) override {}
  void visit(GeometryNode&) override {}
  void visit(Drawable&) override;
  void visit(SphereGeometry&) override;
  void visit(CurveGeometry&) override;
  void visit(CylinderGeometry&) override {}
  void visit(MeshGeometry&) override;
  void visit(TextLabel2D&) override {}
  void visit(TextLabel3D&) override {}
  void visit(LineStripGeometry&) override;
  void visit(WideLineGeometry&) override;

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
