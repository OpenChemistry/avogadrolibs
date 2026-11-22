/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_PLYVISITOR_H
#define AVOGADRO_RENDERING_PLYVISITOR_H

#include "tessellatingvisitor.h"

#include "camera.h"

#include <iosfwd>
#include <string>

namespace Avogadro::Rendering {

/**
 * @class PLYVisitor plyvisitor.h <avogadro/rendering/plyvisitor.h>
 * @brief Visitor that visits scene elements and creates an ASCII PLY file.
 *
 * The scene is tessellated by TessellatingVisitor; write() and end() output
 * all the resulting triangles as one PLY mesh with per-vertex positions,
 * normals and RGBA colours (uchar).
 *
 * The default format is binary_little_endian, written byte by byte so it does
 * not depend on the host byte order: 28 bytes per vertex (6 floats, 4 uchar)
 * and 13 bytes per face (uchar 3, 3 uint). Detailed scenes have millions of
 * vertices, so prefer write() to a stream over end(). ASCII is available with
 * setBinary(false).
 */

class AVOGADRORENDERING_EXPORT PLYVisitor : public TessellatingVisitor
{
public:
  explicit PLYVisitor(const Camera& camera);
  ~PLYVisitor() override;

  /**
   * The output transform (offset and scale, see TessellatingVisitor) is
   * applied to positions: p_out = (p - center) * scale. setCenter() and
   * center() are the older names of setOffset() and offset().
   * @{
   */
  void setCenter(const Vector3f& center) { setOffset(center); }
  Vector3f center() const { return offset(); }
  /** @} */

  /** Binary little-endian (default) or ASCII output. */
  void setBinary(bool binary) { m_binary = binary; }
  bool binary() const { return m_binary; }

  /**
   * Stream the PLY file for everything visited since begin().
   * @return false if the stream failed.
   */
  bool write(std::ostream& out) const;

  /** The whole PLY file in memory (via write()); binary data if binary(). */
  std::string end();

  void setCamera(const Camera& c) { m_camera = c; }
  Camera camera() const { return m_camera; }

  void setBackgroundColor(const Vector3ub& c) { m_backgroundColor = c; }
  void setAmbientColor(const Vector3ub& c) { m_ambientColor = c; }
  void setAspectRatio(float ratio) { m_aspectRatio = ratio; }

private:
  Camera m_camera;
  Vector3ub m_backgroundColor;
  Vector3ub m_ambientColor;
  float m_aspectRatio;
  bool m_binary = true;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif // AVOGADRO_RENDERING_PLYVISITOR_H
