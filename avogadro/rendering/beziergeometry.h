/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_BEZIERGEOMETRY_H
#define AVOGADRO_RENDERING_BEZIERGEOMETRY_H

#include "bufferobject.h"
#include "drawable.h"
#include "shader.h"
#include "shaderprogram.h"
#include <avogadro/core/vector.h>
#include <list>
#include <map>
#include <vector>

namespace Avogadro {
namespace Rendering {

struct ShaderInfo
{
  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;
};

struct BezierPoint
{
  BezierPoint(const Vector3f& p, const Vector3ub& c, float r)
    : pos(p), color(c), radius(r)
  {
    flat = r < 0;
  }

  Vector3f pos;
  Vector3ub color;
  bool flat;
  // use GL_POINTS
  float radius;
};

struct BezierLine
{
  BezierLine() : dirty(true) {}

  ~BezierLine()
  {
    for (auto& p : points) {
      delete p;
    }
  }
  void add(BezierPoint* point)
  {
    points.push_back(point);
    dirty = true;
  }
  std::list<BezierPoint*> points;
  bool dirty;
  BufferObject vbo;
  BufferObject ibo; // EBO/IBO
  size_t numberOfVertices;
  size_t numberOfIndices;
};

class AVOGADRORENDERING_EXPORT BezierGeometry : public Drawable
{
public:
  BezierGeometry();
  ~BezierGeometry() override;
  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor& visitor) override;
  /**
   * @brief Render the cylinder geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;
  /**
   * Return the primitives that are hit by the ray.
   * @param rayOrigin Origin of the ray.
   * @param rayEnd End point of the ray.
   * @param rayDirection Normalized direction of the ray.
   * @return Sorted collection of primitives that were hit.
   */
  std::multimap<float, Identifier> hits(
    const Vector3f& rayOrigin, const Vector3f& rayEnd,
    const Vector3f& rayDirection) const override;

  void addPoint(const Vector3f& pos, const Vector3ub& color, float radius,
                size_t i);

private:
  std::vector<BezierLine*> m_bezierLines;
  std::map<size_t, size_t> m_indexMap;
  ShaderInfo m_shaderInfo;
  bool m_dirty;
  std::vector<size_t> m_factorials;

  void update(int index);

  Vector3f computeBezierPoint(float t, const std::list<BezierPoint*>& points);
  void processShaderError(bool error);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
