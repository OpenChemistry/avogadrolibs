/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "curvegeometry.h"

#include "camera.h"
#include "scene.h"
#include "visitor.h"

namespace {
#include "cylinders_fs.h"
#include "cylinders_vs.h"
} // namespace
#include "avogadrogl.h"

#include <iostream>
#include <queue>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

using Core::Array;

const size_t CurveGeometry::SKIPPED = 1;

CurveGeometry::CurveGeometry() : m_dirty(true), m_canBeFlat(true) {}
CurveGeometry::CurveGeometry(bool flat) : m_dirty(true), m_canBeFlat(flat) {}

CurveGeometry::~CurveGeometry()
{
  for (auto& l : m_lines) {
    delete l;
  }
}

std::vector<ColorNormalVertex> CurveGeometry::computeCirclePoints(
  const Eigen::Affine3f& a, const Eigen::Affine3f& b, bool flat) const
{
  unsigned int circleResolution = flat ? 1 : 12;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  std::vector<ColorNormalVertex> result;

  for (unsigned int i = 0; i < circleResolution; ++i) {
    float theta = i * resolutionRadians;
    Vector3f circle = Vector3f(std::cos(theta), 0.0f, std::sin(theta));
    ColorNormalVertex vert1;
    vert1.normal = a.linear() * circle;
    vert1.vertex = a * circle;
    vert1.color = Vector3ub(0.7f, 0.7f, 0.7f);
    result.push_back(vert1);

    ColorNormalVertex vert2;
    vert2.normal = b.linear() * circle;
    vert2.vertex = b * circle;
    vert2.color = Vector3ub(0.7f, 0.7f, 0.7f);
    result.push_back(vert2);
  }
  return result;
}

float CurveGeometry::computeScale(size_t, float, float scale) const
{
  return scale;
}

void CurveGeometry::update(int index)
{
  // compute the middle points
  Line* line = m_lines[index];
  unsigned int lineResolution = line->flat ? 20 : 15;
  size_t qttyPoints = line->points.size();

  const size_t qttySegments = lineResolution * qttyPoints;
  Vector3f previous;
  std::vector<Eigen::Affine3f> points;
  size_t top = qttyPoints <= 4 ? 0 : line->points.size() - 4;
  auto it = line->points.begin();
  for (size_t i = SKIPPED; i < top; ++i) {
    for (size_t j = 0; j < lineResolution; ++j) {
      float t = (i * lineResolution + j) / float(qttySegments);
      auto p = computeCurvePoint(t, line->points);
      if (i > SKIPPED) {
        Eigen::Matrix3f m;
        m.col(1) = (p - previous).normalized();
        m.col(0) = m.col(1).unitOrthogonal() * -1.0f;
        if (i > SKIPPED + 1) {
          const auto& previousAngle = points.back().linear().col(0);
          float angle = previousAngle.dot(m.col(0));
          // avoid nans
          if (std::isnan(angle)) {
            m.col(0) = previousAngle;
            break;
            // if angle > 90 flip it
          } else if (angle <= 0.0f) {
            m.col(0) *= -1.0f;
          }
          angle = previousAngle.dot(m.col(0));
          float degrees =
            (std::acos(angle / (m.col(0).norm() * previousAngle.norm())) *
             RAD_TO_DEG_F);
          // if angle is > 25º get the bisector
          while (degrees > 25.0f) {
            m.col(0) = (m.col(0) + previousAngle).normalized();
            angle = previousAngle.dot(m.col(0));
            degrees =
              (std::acos(angle / (m.col(0).norm() * previousAngle.norm())) *
               RAD_TO_DEG_F);
          }
        }
        m.col(2) = m.col(0).cross(m.col(1)) * -1.0f;
        Eigen::Affine3f affine;
        affine.translation() = p;
        affine.linear() = m;
        float r = !m_canBeFlat || !line->flat
                    ? computeScale(i, j / static_cast<float>(lineResolution),
                                   line->radius)
                    : 0.01f;
        affine.scale(r);
        points.push_back(affine);
      }
      previous = p;
    }
    ++it;
  }

  // prepare VBO and EBO
  std::vector<unsigned int> indices;
  std::vector<ColorNormalVertex> vertices;

  it = line->points.begin();
  if (line->points.size() > 3) {
    it = std::next(it, 3);
  }
  for (size_t i = 1; i < points.size(); ++i) {
    if (i % lineResolution == 0) {
      ++it;
    }
    std::vector<ColorNormalVertex> radials =
      computeCirclePoints(points[i], points[i - 1], line->flat);
    for (auto r : radials) {
      r.color = (*it)->color;
      vertices.push_back(r);
    }
    const unsigned int tubeStart = static_cast<unsigned int>(
      vertices.size() - (line->flat && m_canBeFlat ? radials.size() : 0));
    for (unsigned int j = 0; j < radials.size() / 2; ++j) {
      unsigned int r1 = j + j;
      unsigned int r2 = (j != 0 ? r1 : radials.size()) - 2;
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

void CurveGeometry::accept(Visitor& visitor)
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

void CurveGeometry::processShaderError(bool error)
{
  if (error) {
    cout << m_shaderInfo.program.error() << endl;
  }
}

void CurveGeometry::render(const Camera& camera)
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

    for (size_t i = 0; i < m_lines.size(); ++i) {
      Line* line = m_lines[i];
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
      if (line->flat && m_canBeFlat) {
        glLineWidth(-line->radius);
      }
      glDrawRangeElements(line->flat && m_canBeFlat ? GL_LINE_STRIP
                                                    : GL_TRIANGLES,
                          0, static_cast<GLuint>(line->numberOfVertices),
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

void CurveGeometry::addPoint(const Vector3f& pos, const Vector3ub& color,
                             float radius, size_t group, size_t id)
{
  if (m_indexMap.find(group) == m_indexMap.end()) {
    m_indexMap[group] = m_lines.size();
    m_lines.push_back(new Line(radius));
  }
  m_lines[m_indexMap[group]]->radius = radius;
  m_lines[m_indexMap[group]]->flat = radius < 0.0f;
  m_lines[m_indexMap[group]]->add(new Point(pos, color, id));
}

Array<Identifier> CurveGeometry::areaHits(const Frustrum& f) const
{
  Array<Identifier> result;
  // Check for intersection.
  for (const auto& line : m_lines) {
    size_t skip = 0;
    std::queue<size_t> previous;
    for (const auto& point : line->points) {
      previous.push(point->id);
      if (skip < 2) {
        ++skip;
        continue;
      }
      int in = 0;
      for (; in < 4; ++in) {
        float dist = (point->pos - f.points[2 * in]).dot(f.planes[in]);
        if (dist > 0.0f) {
          // Outside of our frustrum, break.
          break;
        }
      }
      if (in == 4) {
        // The center is within the four planes that make our frustrum - hit.
        Identifier id;
        id.molecule = m_identifier.molecule;
        id.type = m_identifier.type;
        id.index = previous.front();
        result.push_back(id);
      }
      previous.pop();
    }
  }
  return result;
}

} // namespace Rendering
} // namespace Avogadro
