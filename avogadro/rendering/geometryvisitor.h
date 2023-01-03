/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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

#ifdef TDX_INTEGRATION
struct SphereColor;
class SphereGeometry;
class CylinderGeometry;
#endif

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
#ifdef TDX_INTEGRATION
  void visit(CylinderGeometry&) override;
#else
  void visit(CylinderGeometry&) override { return; }
#endif
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
#ifdef TDX_INTEGRATION
  /** 
   * <<API Extension for TDX>>
   * Calculates the bounding box of the molecule.
   * @param minX [out] minimum X coordinate of the box diagonal
   * @param minY [out] minimum Y coordinate of the box diagonal
   * @param minZ [out] minimum Z coordinate of the box diagonal
   * @param maxX [out] maximum X coordinate of the box diagonal
   * @param maxY [out] maximum Y coordinate of the box diagonal
   * @param maxZ [out] maximum Z coordinate of the box diagonal
   * @param flags [in] flags informing which atoms will be included
   * in the bounding box.
   */
  void boundingBox(double &minX, 
				   double &minY,
				   double &minZ,
				   double &maxX,
                   double &maxY,
				   double &maxZ,
                   const std::vector<bool> &flags) const;

  /**
   * <<API Extension for TDX>>
   * Hit-tests underlying geometry.
   * @param rayOrigin Origin of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Distance to the intersection point lying on the passed ray.
   * If returned value is less than zero, then there is no intersection.
   */
  float hit(const Vector3f &rayOrigin, 
			const Vector3f &rayDirection,
			const float rayLength);
#endif
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
#ifdef TDX_INTEGRATION
  std::vector<SphereColor> m_spheres;
  std::vector<SphereGeometry> m_sphereGeometries;
  std::vector<CylinderGeometry> m_cylinderGeometries;
#endif
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYVISITOR_H
