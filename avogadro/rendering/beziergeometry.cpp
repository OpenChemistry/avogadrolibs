/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "beziergeometry.h"

#include "camera.h"
#include "scene.h"
#include "visitor.h"
namespace {
#include "cylinders_fs.h"
#include "cylinders_vs.h"
} // namespace
#include "avogadrogl.h"

#include <iostream>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

BezierGeometry::BezierGeometry() : m_dirty(true) {}

BezierGeometry::~BezierGeometry()
{
  for (auto& l : m_bezierLines) {
    delete l;
  }
}

void BezierGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void checkShaderInfo(ShaderInfo& shaderInfo, const std::string& fs,
                     const std::string& vs)
{
  if (shaderInfo.vertexShader.type() == Shader::Unknown) {
    shaderInfo.vertexShader.setType(Shader::Vertex);
    shaderInfo.vertexShader.setSource(vs);
    shaderInfo.fragmentShader.setType(Shader::Fragment);
    shaderInfo.fragmentShader.setSource(fs);
    if (!shaderInfo.vertexShader.compile())
      cout << shaderInfo.vertexShader.error() << endl;
    if (!shaderInfo.fragmentShader.compile())
      cout << shaderInfo.fragmentShader.error() << endl;
    shaderInfo.program.attachShader(shaderInfo.vertexShader);
    shaderInfo.program.attachShader(shaderInfo.fragmentShader);
    if (!shaderInfo.program.link())
      cout << shaderInfo.program.error() << endl;
  }
}

void BezierGeometry::processShaderError(bool error)
{
  if (error) {
    cout << m_shaderInfo.program.error() << endl;
  }
}

size_t BinomialCoefficient(const size_t n, const size_t k)
{
  std::vector<size_t> aSolutions(k + 1);
  aSolutions[0] = n - k + 1;
  for (size_t i = 1; i < k; ++i) {
    aSolutions[i] = aSolutions[i - 1] * (n - k + 1 + i) / (i + 1);
  }

  return aSolutions[k - 1];
}

Vector3f BezierGeometry::computeBezierPoint(
  float t, const std::list<BezierPoint*>& points)
{
  Vector3f h;
  h << 1.0f, 1.0f, 1.0f;
  float u = 1.0f - t;
  float n1 = points.size();
  float w = 1.0f / n1;
  float k = 0.0f;
  Vector3f Q;
  Q << w, w, w;
  for (const auto& p : points) {
    for (size_t i = 0; i < 3; ++i) {
      h[i] = h[i] * t * (n1 - k) * w;
      h[i] = h[i] / (k * u * w + h[i]);
      Q[i] = (1.0f - h[i]) * Q[i] + h[i] * p->pos[i];
    }
    k += 1.0f;
  }
  return Q;
}

void BezierGeometry::update(int index)
{
  // compute the intermidian bezier points
  BezierLine* line = m_bezierLines[index];
  unsigned int lineResolution = 12;
  size_t qttyPoints = line->points.size();
  size_t qttySegments = lineResolution * qttyPoints;
  std::vector<Vector3f> points(qttySegments);
  for (size_t i = 0; i < qttyPoints; ++i) {
    for (size_t j = 0; j < lineResolution; ++j) {
      points[i * lineResolution + j] = computeBezierPoint(
        (i * lineResolution + j) / float(qttySegments), line->points);
    }
  }

  // prepare VBO and EBO
  std::vector<unsigned int> indices;
  std::vector<ColorNormalVertex> vertices;
  unsigned int circleResolution = 20;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  std::vector<Vector3f> radials(circleResolution);

  auto it = line->points.begin();
  for (size_t i = 1; i < qttySegments; ++i) {
    if (i % lineResolution == 0) {
      ++it;
    }
    const BezierPoint* point = *it;
    const Vector3f& position1 = points[i - 1];
    const Vector3f& position2 = points[i];
    const Vector3f direction = (position2 - position1).normalized();
    float radius = point->radius;

    Vector3f radial = direction.unitOrthogonal() * radius;
    Eigen::AngleAxisf transform(resolutionRadians, direction);
    for (unsigned int j = 0; j < circleResolution; ++j) {
      radials[j] = radial;
      radial = transform * radial;
    }

    ColorNormalVertex vert1(point->color, -direction, position1);
    ColorNormalVertex vert2(point->color, -direction, position1);
    for (const auto& normal : radials) {
      vert1.normal = normal;
      vert1.vertex = position1 + normal;
      vertices.push_back(vert1);

      vert2.normal = normal;
      vert2.vertex = position2 + normal;
      vertices.push_back(vert2);
    }

    // Now to stitch it together. we select the indices
    const unsigned int tubeStart = static_cast<unsigned int>(vertices.size());
    for (unsigned int j = 0; j < circleResolution; ++j) {
      unsigned int r1 = j + j;
      unsigned int r2 = (j != 0 ? r1 : circleResolution + circleResolution) - 2;
      indices.push_back(tubeStart + r1);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2);

      indices.push_back(tubeStart + r2);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2 + 1);
    }
  }

  line->vbo.upload(vertices, BufferObject::ArrayBuffer);
  line->ibo.upload(indices, BufferObject::ElementArrayBuffer);
  line->numberOfVertices = vertices.size();
  line->numberOfIndices = indices.size();

  line->dirty = false;
}

void BezierGeometry::render(const Camera& camera)
{
  if (m_dirty) {
    checkShaderInfo(m_shaderInfo, cylinders_fs, cylinders_vs);
    m_dirty = false;
  }
  if (!m_dirty) {
    processShaderError(!m_shaderInfo.program.bind());
    processShaderError(!m_shaderInfo.program.setUniformValue(
      "modelView", camera.modelView().matrix()));
    processShaderError(!m_shaderInfo.program.setUniformValue(
      "projection", camera.projection().matrix()));
    Eigen::Matrix3f normalMatrix =
      camera.modelView().linear().inverse().transpose();
    processShaderError(
      !m_shaderInfo.program.setUniformValue("normalMatrix", normalMatrix));

    for (size_t i = 0; i < m_bezierLines.size(); ++i) {
      BezierLine* line = m_bezierLines[i];
      if (line->dirty) {
        update(i);
      }

      line->vbo.bind();
      line->ibo.bind();

      processShaderError(!m_shaderInfo.program.enableAttributeArray("vertex"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "vertex", ColorNormalVertex::vertexOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize));

      processShaderError(!m_shaderInfo.program.enableAttributeArray("color"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "color", ColorNormalVertex::colorOffset(), sizeof(ColorNormalVertex),
        UCharType, 3, ShaderProgram::Normalize));

      processShaderError(!m_shaderInfo.program.enableAttributeArray("normal"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "normal", ColorNormalVertex::normalOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize));

      glDrawRangeElements(GL_TRIANGLES, 0,
                          static_cast<GLuint>(line->numberOfVertices),
                          static_cast<GLsizei>(line->numberOfIndices),
                          GL_UNSIGNED_INT, reinterpret_cast<const GLvoid*>(0));
      line->vbo.release();
      line->ibo.release();
      m_shaderInfo.program.disableAttributeArray("vector");
      m_shaderInfo.program.disableAttributeArray("color");
      m_shaderInfo.program.disableAttributeArray("normal");
    }
    m_shaderInfo.program.release();
  }
}

std::multimap<float, Identifier> BezierGeometry::hits(const Vector3f&,
                                                      const Vector3f&,
                                                      const Vector3f&) const
{
  return std::multimap<float, Identifier>();
}

void BezierGeometry::addPoint(const Vector3f& pos, const Vector3ub& color,
                              float radius, size_t i)
{
  if (m_indexMap.find(i) == m_indexMap.end()) {
    m_indexMap[i] = m_bezierLines.size();
    m_bezierLines.push_back(new BezierLine());
  }
  m_bezierLines[m_indexMap[i]]->add(new BezierPoint(pos, color, radius));
}

} // namespace Rendering
} // namespace Avogadro
