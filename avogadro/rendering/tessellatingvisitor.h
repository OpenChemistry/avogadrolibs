/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_TESSELLATINGVISITOR_H
#define AVOGADRO_RENDERING_TESSELLATINGVISITOR_H

#include "visitor.h"

#include <avogadro/core/vector.h>

#include <string>
#include <vector>

namespace Avogadro {
namespace Rendering {

/**
 * @struct TessellatedMesh tessellatingvisitor.h
 * <avogadro/rendering/tessellatingvisitor.h>
 * @brief A triangle mesh produced from one drawable of the scene.
 *
 * All arrays except @p indices are parallel (one entry per vertex).
 */
struct TessellatedMesh
{
  /** The kind of drawable: "spheres", "cylinders", "mesh", "cartoon",
   *  "curves", "dashedlines", "arrows", "lines", ... */
  std::string name;
  std::vector<Vector3f> positions;
  std::vector<Vector3f> normals;
  /** RGBA, the alpha channel is the opacity. */
  std::vector<Vector4ub> colors;
  /** Triangle list (three indices per triangle) into the vertex arrays. */
  std::vector<unsigned int> indices;
};

/**
 * @class TessellatingVisitor tessellatingvisitor.h
 * <avogadro/rendering/tessellatingvisitor.h>
 * @brief Visitor that converts every drawable into triangle meshes.
 *
 * This is the shared basis of the mesh-based scene exporters (PLY, glTF, ...).
 * One TessellatedMesh is recorded per visited drawable (curve geometry with
 * several lines is merged into a single mesh), in visiting order. Colors are
 * not shaded: lighting is left to the consumer.
 *
 * Text labels and volume rendering cannot be expressed as triangle meshes and
 * are skipped.
 */
class AVOGADRORENDERING_EXPORT TessellatingVisitor : public Visitor
{
public:
  TessellatingVisitor();
  ~TessellatingVisitor() override;

  /** Discard all meshes recorded so far. Equivalent to clear(). */
  void begin();
  void clear();

  const std::vector<TessellatedMesh>& meshes() const { return m_meshes; }

  /**
   * Geometric tolerance in Angstrom: the largest distance between a
   * tessellated sphere or cylinder surface and the true surface. Unless fixed
   * explicitly (below), the sphere subdivision level and the cylinder side
   * count are chosen per primitive from its radius to meet this tolerance.
   * Non-finite or non-positive values are ignored. Default 0.05.
   * @{
   */
  void setTessellationTolerance(float angstrom);
  float tessellationTolerance() const { return m_tolerance; }
  /** @} */

  /**
   * Range (0 to 6) of icosphere subdivision levels the adaptive choice may
   * use. Default 1 (42 vertices) to 5 (10242 vertices).
   */
  void setSphereLevelRange(unsigned int minLevel, unsigned int maxLevel);

  /**
   * Smallest level in the range whose maximum sagitta,
   * radius * (1 - cos(theta / 2)) with theta the largest angle subtended by
   * an edge of that level's icosphere, is within the tolerance (the maximum
   * level if none is).
   */
  unsigned int sphereLevelForRadius(float radius);

  /** The largest angle (radians) subtended by an edge of a level's mesh. */
  float sphereMaxEdgeAngle(unsigned int level);

  /**
   * Use a fixed number of icosphere subdivisions (0 to 6) for every sphere,
   * instead of the adaptive choice. Level 3 has 1280 triangles, 642 vertices.
   * @{
   */
  void setSphereSubdivisions(unsigned int level);
  /** The fixed level, or the minimum level of the range when adaptive. */
  unsigned int sphereSubdivisions() const;
  void useAdaptiveSpheres() { m_fixedSphereLevel = -1; }
  /** @} */

  /**
   * Use a fixed number of sides (at least 3) for every cylinder instead of
   * the adaptive choice, which is the smallest n >= 8 (at most 48) with
   * radius * (1 - cos(pi / n)) within the tolerance.
   * @{
   */
  void setCylinderSides(unsigned int sides);
  unsigned int cylinderSides() const { return m_fixedCylinderSides; }
  void useAdaptiveCylinders() { m_fixedCylinderSides = 0; }
  unsigned int cylinderSidesForRadius(float radius) const;
  /** @} */

  /**
   * Tube radius (in scene units, Angstrom) of one pixel of GL line width.
   * Dashed lines, line strips and flat curves have no world-space width, only
   * a width in pixels, so their tubes get radius lineRadius * width (width is
   * at least 1). WideLineGeometry already has a world-space width and ignores
   * this value. Default 0.02.
   * @{
   */
  void setLineRadius(float radius);
  float lineRadius() const { return m_lineRadius; }
  /** @} */

  void visit(Node&) override { return; }
  void visit(GroupNode&) override { return; }
  void visit(GeometryNode&) override { return; }
  void visit(Drawable&) override { return; }
  void visit(SphereGeometry& geometry) override;
  void visit(CurveGeometry& geometry) override;
  void visit(CylinderGeometry& geometry) override;
  void visit(MeshGeometry& geometry) override;
  void visit(TextLabel2D&) override { return; }
  void visit(TextLabel3D&) override { return; }
  void visit(LineStripGeometry& geometry) override;
  void visit(WideLineGeometry& geometry) override;
  void visit(DashedLineGeometry& geometry) override;
  void visit(ArrowGeometry& geometry) override;
  void visit(VolumeGeometry&) override { return; }

private:
  struct Icosphere
  {
    bool built = false;
    std::vector<Vector3f> vertices;
    std::vector<unsigned int> indices;
    float maxEdgeAngle = 0.0f;
  };
  const Icosphere& icosphere(unsigned int level);

  std::vector<TessellatedMesh> m_meshes;

  float m_tolerance = 0.05f;
  unsigned int m_minLevel = 1;
  unsigned int m_maxLevel = 5;
  int m_fixedSphereLevel = -1;           // -1: adaptive
  unsigned int m_fixedCylinderSides = 0; // 0: adaptive
  float m_lineRadius = 0.02f;

  // Unit icospheres with shared vertices, built lazily per level.
  std::vector<Icosphere> m_icospheres;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_TESSELLATINGVISITOR_H
