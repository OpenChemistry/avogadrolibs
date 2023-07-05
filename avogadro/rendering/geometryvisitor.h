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

struct SphereColor;

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
  void boundingBox(double& minX, double& minY, double& minZ, double& maxX,
                   double& maxY, double& maxZ,
                   const std::vector<bool>& flags) const;

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
  std::vector<SphereColor> m_spheres;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GEOMETRYVISITOR_H
