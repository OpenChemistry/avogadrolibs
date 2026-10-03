/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_PLYVISITOR_H
#define AVOGADRO_RENDERING_PLYVISITOR_H

#include "tessellatingvisitor.h"

#include "camera.h"

#include <string>

namespace Avogadro {
namespace Rendering {

/**
 * @class PLYVisitor plyvisitor.h <avogadro/rendering/plyvisitor.h>
 * @brief Visitor that visits scene elements and creates an ASCII PLY file.
 *
 * The scene is tessellated by TessellatingVisitor; end() writes all the
 * resulting triangles as one PLY mesh with per-vertex positions, normals and
 * RGBA colours.
 */

class AVOGADRORENDERING_EXPORT PLYVisitor : public TessellatingVisitor
{
public:
  explicit PLYVisitor(const Camera& camera);
  ~PLYVisitor() override;

  /** Return the PLY text for everything visited since begin(). */
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
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_PLYVISITOR_H
