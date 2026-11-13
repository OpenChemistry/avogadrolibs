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
namespace Core {
class Molecule;
}
} // namespace Avogadro

namespace Avogadro::Rendering {

/**
 * @struct TessellatedMesh tessellatingvisitor.h
 * <avogadro/rendering/tessellatingvisitor.h>
 * @brief A triangle mesh produced from one drawable of the scene.
 *
 * All arrays except @p indices are parallel (one entry per vertex).
 *
 * TessellatingVisitor guarantees, for every mesh it records, that consumers
 * need not check any of the following: the arrays are parallel and not empty;
 * positions are finite; normals are finite and of unit length (a missing or
 * degenerate normal is replaced by +Z); indices come in whole triangles
 * and refer to existing vertices. Triangles that use a vertex with a
 * non-finite position are dropped.
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
  /**
   * True if the triangles form closed, outward-facing (counter-clockwise seen
   * from outside) surfaces, so that back faces are never visible from
   * outside: spheres, and cylinders with end caps. Open surfaces (curves,
   * ribbons, isosurfaces, ...) may be seen from both sides.
   */
  bool closed = false;
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
   * The default export scale: Molecular Nodes (Blender) uses a world_scale of
   * 0.1, i.e. 1 Angstrom = 0.1 Blender units.
   */
  static constexpr float MolecularNodesScale = 0.1f;

  /**
   * Output transform for the exporters, applied to positions when writing
   * only: p_out = (p - offset) * scale. Normals are unchanged. The tessellated
   * meshes (and the tessellation tolerance) stay in Angstrom. The defaults
   * (origin, 1) leave positions as they are. Non-finite offset components are
   * zeroed; a non-finite or non-positive scale is ignored (so the scale is
   * always positive).
   * @{
   */
  void setOffset(const Vector3f& offset);
  Vector3f offset() const { return m_offset; }
  void setScale(float scale);
  float scale() const { return m_scale; }
  /** @} */

  /**
   * Set the offset to the center of geometry of the atoms of @p molecule, so
   * that several exports of one molecule line up whatever is drawn. Without
   * atoms (or without a molecule) the center of the bounding box of meshes()
   * is used, so call this after visiting the scene.
   */
  void centerOn(const Core::Molecule* molecule);

  /**
   * Axis-aligned bounding box of all vertices in meshes().
   * @return false (leaving the arguments untouched) if there are none.
   */
  bool bounds(Vector3f& minimum, Vector3f& maximum) const;

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
   * How a cylinder with two different end colours is coloured. Gradient (the
   * default) interpolates the colour along the cylinder, as on screen. Split
   * makes two single-colour tubes, each covering half of the cylinder, so
   * that every triangle has a uniform colour.
   * @{
   */
  enum class CylinderColoring
  {
    Gradient,
    Split
  };
  void setCylinderColoring(CylinderColoring coloring)
  {
    m_cylinderColoring = coloring;
  }
  CylinderColoring cylinderColoring() const { return m_cylinderColoring; }
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

  void visit(Node&) override {}
  void visit(GroupNode&) override {}
  void visit(GeometryNode&) override {}
  void visit(Drawable&) override {}
  void visit(SphereGeometry& geometry) override;
  void visit(CurveGeometry& geometry) override;
  void visit(CylinderGeometry& geometry) override;
  void visit(MeshGeometry& geometry) override;
  void visit(TextLabel2D&) override {}
  void visit(TextLabel3D&) override {}
  void visit(LineStripGeometry& geometry) override;
  void visit(WideLineGeometry& geometry) override;
  void visit(DashedLineGeometry& geometry) override;
  void visit(ArrowGeometry& geometry) override;
  void visit(VolumeGeometry&) override {}

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
  CylinderColoring m_cylinderColoring = CylinderColoring::Gradient;
  float m_lineRadius = 0.02f;
  Vector3f m_offset = Vector3f::Zero();
  float m_scale = 1.0f;

  // Unit icospheres with shared vertices, built lazily per level.
  std::vector<Icosphere> m_icospheres;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif // AVOGADRO_RENDERING_TESSELLATINGVISITOR_H
