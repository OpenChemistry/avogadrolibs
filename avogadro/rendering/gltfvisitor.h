/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GLTFVISITOR_H
#define AVOGADRO_RENDERING_GLTFVISITOR_H

#include "tessellatingvisitor.h"

#include "camera.h"

#include <iosfwd>
#include <optional>
#include <string>

namespace Avogadro::Rendering {

/**
 * @class GltfVisitor gltfvisitor.h <avogadro/rendering/gltfvisitor.h>
 * @brief Visitor that visits scene elements and writes a binary glTF 2.0
 * (.glb) file.
 *
 * The scene is tessellated by TessellatingVisitor; write() outputs one glTF
 * node and mesh per drawable (named after the kind of drawable: "spheres",
 * "cylinders", "mesh", "cartoon", ...). Triangles whose three vertices share
 * one colour are grouped by colour into primitives without COLOR_0, whose
 * material carries the colour as baseColorFactor (linear, as glTF requires;
 * BLEND if translucent, else OPAQUE), so that viewers that ignore vertex
 * colours still show it. Materials are shared across the file and named after
 * their sRGB colour ("#3050F8", plus the alpha "80" if translucent). Triangles
 * with differing vertex colours (gradients, coloured surfaces) share one more
 * primitive per mesh with a COLOR_0 attribute (normalized unsigned shorts,
 * linear) and a white "opaque" or "translucent" material. The primitives of a
 * mesh share its POSITION and NORMAL accessors. Everything but closed meshes
 * (TessellatedMesh::closed) is double sided. All numbers are written
 * little-endian regardless of the host byte order.
 *
 * Optionally (setCamera()) a camera node is added, positioned like the view
 * the camera was taken from.
 *
 * Positions are written as p_out = (p - offset()) * scale() (see
 * TessellatingVisitor), and the transform is recorded in asset.extras so that
 * a consumer can recover Angstrom coordinates. The defaults (offset 0, scale 1)
 * leave positions as they are.
 */
class AVOGADRORENDERING_EXPORT GltfVisitor : public TessellatingVisitor
{
public:
  GltfVisitor();
  ~GltfVisitor() override;

  /**
   * Add a camera node looking at the scene the way @p camera does. Only the
   * model view and projection matrices are used.
   * @{
   */
  void setCamera(const Camera& camera) { m_camera = camera; }
  void clearCamera() { m_camera.reset(); }
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
  std::optional<Camera> m_camera;
  mutable std::string m_error;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif // AVOGADRO_RENDERING_GLTFVISITOR_H
