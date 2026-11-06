/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GLTFVISITOR_H
#define AVOGADRO_RENDERING_GLTFVISITOR_H

#include "tessellatingvisitor.h"

#include "camera.h"

#include <iosfwd>
#include <string>

namespace Avogadro::Rendering {

/**
 * @class GltfVisitor gltfvisitor.h <avogadro/rendering/gltfvisitor.h>
 * @brief Visitor that visits scene elements and writes a binary glTF 2.0
 * (.glb) file.
 *
 * The scene is tessellated by TessellatingVisitor; write() outputs one glTF
 * node, mesh and primitive per drawable (named after the kind of drawable:
 * "spheres", "cylinders", "mesh", "cartoon", ...) with POSITION, NORMAL and
 * COLOR_0 attributes. Vertex colours are converted from sRGB to linear, as
 * glTF requires, and stored as normalized unsigned shorts. Primitives with any
 * translucent vertex use an alphaMode BLEND material, the others OPAQUE;
 * everything but spheres is double sided. All numbers are written
 * little-endian regardless of the host byte order.
 *
 * Optionally (setCamera()) a camera node is added, positioned like the view
 * the camera was taken from.
 *
 * Positions are written as p_out = (p - offset) * scale, and the transform is
 * recorded in asset.extras so that a consumer can recover Angstrom
 * coordinates. The defaults (offset 0, scale 1) leave positions as they are.
 */
class AVOGADRORENDERING_EXPORT GltfVisitor : public TessellatingVisitor
{
public:
  GltfVisitor();
  ~GltfVisitor() override;

  /**
   * Output transform, applied to positions (and the camera) when writing
   * only: p_out = (p - offset) * scale. Normals are unchanged. The tessellated
   * meshes (and the tessellation tolerance) stay in Angstrom. A non-finite or
   * non-positive scale is ignored; non-finite offset components are zeroed.
   * @{
   */
  void setOffset(const Vector3f& offset);
  Vector3f offset() const { return m_offset; }
  void setScale(float scale);
  float scale() const { return m_scale; }
  /** @} */

  /**
   * Add a camera node looking at the scene the way @p camera does. Only the
   * model view and projection matrices are used.
   * @{
   */
  void setCamera(const Camera& camera);
  void clearCamera() { m_hasCamera = false; }
  bool hasCamera() const { return m_hasCamera; }
  /** @} */

  /**
   * Stream the .glb file for everything visited since begin().
   * @return false if the stream failed or the data does not fit in a GLB
   * file (4 GB); error() then describes the problem. Nothing is written in
   * the second case.
   */
  bool write(std::ostream& out) const;

  /** The whole .glb file in memory (via write()); empty on failure. */
  std::string end();

  /** A description of why the last write() failed, empty if it did not. */
  std::string error() const { return m_error; }

private:
  Camera m_camera;
  bool m_hasCamera = false;
  Vector3f m_offset = Vector3f::Zero();
  float m_scale = 1.0f;
  mutable std::string m_error;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif // AVOGADRO_RENDERING_GLTFVISITOR_H
