/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CURVEGEOMETRY_H
#define AVOGADRO_RENDERING_CURVEGEOMETRY_H

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

struct Point
{
  Point(const Vector3f& p, const Vector3ub& c, size_t i)
    : pos(p), color(c), id(i)
  {}
  Vector3f pos;
  Vector3ub color;
  size_t id;
};

struct Line
{
  Line() : radius(0.0f), flat(true), dirty(true) {}
  Line(float r) : radius(r), dirty(true) { flat = r < 0.0f; }

  ~Line()
  {
    for (auto& p : points) {
      delete p;
    }
  }
  void add(Point* point)
  {
    points.push_back(point);
    dirty = true;
  }
  std::list<Point*> points;
  bool dirty;
  bool flat; // use GL_POINTS
  float radius;
  BufferObject vbo;
  BufferObject ibo; // EBO/IBO
  size_t order;
  size_t numberOfVertices;
  size_t numberOfIndices;
};

class AVOGADRORENDERING_EXPORT CurveGeometry : public Drawable
{
public:
  CurveGeometry();
  CurveGeometry(bool flat);
  ~CurveGeometry() override;
  /**
   * Accept a visit from our friendly visitor.
   */
  void accept(Visitor& visitor) override;
  /**
   * @brief Render the cylinder geometry.
   * @param camera The current camera to be used for rendering.
   */
  void render(const Camera& camera) override;

  void addPoint(const Vector3f& pos, const Vector3ub& color, float radius,
                size_t group, size_t id);
  const std::vector<Line*>& lines() const { return m_lines; };

  const static size_t SKIPPED;

protected:
  std::vector<Line*> m_lines;
  std::map<size_t, size_t> m_indexMap;
  ShaderInfo m_shaderInfo;
  bool m_dirty;
  bool m_canBeFlat;

  virtual void update(int index);
  virtual Vector3f computeCurvePoint(float t,
                                     const std::list<Point*>& points) const = 0;
  virtual std::vector<ColorNormalVertex> computeCirclePoints(
    const Eigen::Affine3f& a, const Eigen::Affine3f& b, bool flat) const;
  virtual float computeScale(size_t index, float t, float scale) const;

  void processShaderError(bool error);

  Core::Array<Identifier> areaHits(const Frustrum& f) const override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
