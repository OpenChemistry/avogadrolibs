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

#include <algorithm>
#include <iostream>
#include <queue>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

using Core::Array;

const size_t CurveGeometry::SKIPPED = 1;

CurveGeometry::CurveGeometry() : m_dirty(true), m_canBeFlat(true)
{
  setRenderPass(SolidPass);
}

CurveGeometry::CurveGeometry(bool flat) : m_dirty(true), m_canBeFlat(flat)
{
  setRenderPass(SolidPass);
}

CurveGeometry::~CurveGeometry()
{
  for (auto& l : m_lines) {
    delete l;
  }
}

size_t CurveGeometry::circleResolution(bool flat) const
{
  return flat ? 1u : (m_sides > 0 ? std::max<size_t>(m_sides, 3) : 12u);
}

void CurveGeometry::appendRingPoints(std::vector<ColorNormalVertex>& result,
                                     const Eigen::Affine3f& frame,
                                     bool flat) const
{
  const size_t resolution = circleResolution(flat);
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(resolution);

  for (size_t i = 0; i < resolution; ++i) {
    float theta = i * resolutionRadians;
    Vector3f circle = Vector3f(std::cos(theta), 0.0f, std::sin(theta));
    ColorNormalVertex vert;
    vert.normal = frame.linear() * circle;
    vert.vertex = frame * circle;
    vert.color = Vector3ub(0, 0, 0);
    result.push_back(vert);
  }
}

void CurveGeometry::appendCirclePoints(std::vector<ColorNormalVertex>& result,
                                       const Eigen::Affine3f& a,
                                       const Eigen::Affine3f& b,
                                       bool flat) const
{
  std::vector<ColorNormalVertex> ringA, ringB;
  appendRingPoints(ringA, a, flat);
  appendRingPoints(ringB, b, flat);
  for (size_t i = 0; i < ringA.size() && i < ringB.size(); ++i) {
    result.push_back(ringA[i]);
    result.push_back(ringB[i]);
  }
}

float CurveGeometry::computeScale(size_t, float, float scale) const
{
  return scale;
}

bool CurveGeometry::isFlatLine(size_t lineIndex) const
{
  return lineIndex < m_lines.size() && m_lines[lineIndex]->flat && m_canBeFlat;
}

namespace {

// One position along the curve, with what it needs to be drawn.
struct CurveSample
{
  Vector3f pos;
  size_t scaleIndex; // control point passed to computeScale()
  float scaleT;      // position within that control point's stretch, [0, 1]
  size_t colorIndex; // control point whose colour the strip ending here uses
};

} // namespace

size_t CurveGeometry::segmentsFor(bool flat) const
{
  const size_t base = m_segmentsPerResidue > 0 ? m_segmentsPerResidue : 15u;
  // flat lines have always been sampled 4/3 as finely
  return flat ? (base * 4 + 1) / 3 : base;
}

Vector3f CurveGeometry::computeSegmentPoint(size_t, float,
                                            const std::vector<Point>&) const
{
  return Vector3f::Zero();
}

void CurveGeometry::tessellate(size_t lineIndex,
                               std::vector<ColorNormalVertex>& vertices,
                               std::vector<unsigned int>& indices) const
{
  vertices.clear();
  indices.clear();
  if (lineIndex >= m_lines.size())
    return;

  const Line* line = m_lines[lineIndex];
  const size_t lineResolution = segmentsFor(line->flat);
  const size_t qttyPoints = line->points.size();
  const bool uniform = hasUniformSegments();

  // Sample q of the curve; the strip between frames i - 1 and i takes the
  // colour of frame i.
  //
  // Uniform splines: there is one segment per control point (see
  // computeSegmentPoint(); the curve runs from the first to the last control
  // point). Segment k is owned by control point k, which is nearest to the
  // whole of it, so a sample at (k, f) uses the type and width of k, and the
  // strip arriving at it the colour of k (of k - 1 at the first sample of a
  // segment, which ends the previous one). The last sample is the end of
  // segment n - 1. Every sample gets a frame; the first one looks towards the
  // second.
  //
  // Otherwise: the original mapping, residue i for t in [i, i + 1) / n and
  // colours starting at control point 3. Sample 0 only seeds the tangent.
  size_t totalSamples = 0;
  size_t top = 0;
  if (uniform) {
    if (qttyPoints >= 2)
      totalSamples = qttyPoints * lineResolution + 1;
  } else {
    // B-spline valid parameter range requires a margin of ~n/6 at the end;
    // for long chains (n >= 24), 4 points suffice
    const size_t margin = std::min<size_t>(4, (qttyPoints + 5) / 6);
    top = qttyPoints <= margin + 2 ? 0 : qttyPoints - margin;
    totalSamples = top > SKIPPED ? (top - SKIPPED) * lineResolution : 0;
  }
  const size_t lastControl = qttyPoints > 0 ? qttyPoints - 1 : 0;
  const size_t firstColor = qttyPoints > 3 ? 3u : 0u;
  const size_t qttySegments = lineResolution * qttyPoints;
  auto sampleAt = [&](size_t q) {
    CurveSample s;
    if (uniform) {
      const size_t k = q / lineResolution;
      const size_t j = q % lineResolution;
      const float f =
        static_cast<float>(j) / static_cast<float>(lineResolution);
      s.pos = computeSegmentPoint(k, f, line->points);
      if (k >= qttyPoints) { // the end of the last segment
        s.scaleIndex = lastControl;
        s.scaleT = 1.0f;
        s.colorIndex = lastControl;
      } else {
        s.scaleIndex = k;
        s.scaleT = f;
        s.colorIndex = j > 0 || k == 0 ? k : k - 1;
      }
    } else {
      const size_t i = SKIPPED + q / lineResolution;
      const size_t j = q % lineResolution;
      const float t = (i * lineResolution + j) / float(qttySegments);
      s.pos = computeCurvePoint(t, line->points);
      s.scaleIndex = i;
      s.scaleT = j / static_cast<float>(lineResolution);
      s.colorIndex =
        q > 0 ? std::min(firstColor + (q - 1) / lineResolution, lastControl)
              : firstColor;
    }
    return s;
  };

  Vector3f previous = Vector3f::Zero();
  std::vector<Eigen::Affine3f> points;
  std::vector<unsigned int> pointColor;
  points.reserve(totalSamples);
  pointColor.reserve(totalSamples);
  bool nanDetected = false;
  for (size_t q = 0; q < totalSamples && !nanDetected; ++q) {
    const CurveSample sample = sampleAt(q);
    const Vector3f p = sample.pos;
    if (q > 0 || (uniform && totalSamples > 1)) {
      Vector3f tangent = q > 0 ? p - previous : sampleAt(1).pos - p;
      if (tangent.squaredNorm() < 1e-10f) {
        previous = p;
        continue;
      }
      Eigen::Matrix3f m;
      m.col(1) = tangent.normalized();
      m.col(0) = m.col(1).unitOrthogonal() * -1.0f;
      if (!points.empty()) {
        const auto& previousAngle = points.back().linear().col(0);
        float angle = previousAngle.dot(m.col(0));
        if (std::isnan(angle)) {
          nanDetected = true;
          break;
        }
        // if angle > 90 flip it
        if (angle <= 0.0f)
          m.col(0) *= -1.0f;
        angle = previousAngle.dot(m.col(0));
        float denom = m.col(0).norm() * previousAngle.norm();
        float cosAngle = std::clamp(angle / denom, -1.0f, 1.0f);
        float degrees = std::acos(cosAngle) * RAD_TO_DEG_F;
        // if angle is > 25 degrees get the bisector
        int maxIter = 10;
        while (degrees > 25.0f && --maxIter > 0) {
          m.col(0) = (m.col(0) + previousAngle).normalized();
          angle = previousAngle.dot(m.col(0));
          denom = m.col(0).norm() * previousAngle.norm();
          cosAngle = std::clamp(angle / denom, -1.0f, 1.0f);
          degrees = std::acos(cosAngle) * RAD_TO_DEG_F;
        }
      }
      m.col(2) = m.col(0).cross(m.col(1)) * -1.0f;
      Eigen::Affine3f affine;
      affine.translation() = p;
      affine.linear() = m;
      float r = !m_canBeFlat || !line->flat
                  ? computeScale(sample.scaleIndex, sample.scaleT, line->radius)
                  : 0.01f;
      affine.scale(r);
      points.push_back(affine);
      pointColor.push_back(static_cast<unsigned int>(sample.colorIndex));
    }
    previous = p;
  }

  if (points.empty())
    return;

  if (line->flat && m_canBeFlat) {
    vertices.reserve(points.size());

    for (size_t i = 0; i < points.size(); ++i) {
      Vector3f normal = points[i].linear().col(0);
      if (normal.squaredNorm() < 1e-10f) {
        normal = Vector3f::UnitX();
      } else {
        normal.normalize();
      }
      vertices.emplace_back(line->points[pointColor[i]].color, normal,
                            points[i].translation());
    }
  } else {
    const size_t resolution = circleResolution(line->flat);
    const size_t segmentCount = points.size() > 1 ? points.size() - 1 : 0;
    // Each ring is shared by the two segments that meet there; it is only
    // duplicated where the colour changes between consecutive segments.
    vertices.reserve((segmentCount + 1) * resolution);
    indices.reserve(segmentCount * resolution * 6);

    std::vector<ColorNormalVertex> ring;
    ring.reserve(resolution);
    auto emitRing = [&](const Eigen::Affine3f& frame, const Vector3ub& color) {
      ring.clear();
      appendRingPoints(ring, frame, line->flat);
      const auto start = static_cast<unsigned int>(vertices.size());
      for (auto& vertex : ring) {
        vertex.color = color;
        vertices.push_back(vertex);
      }
      return start;
    };

    unsigned int previousRing = 0;
    Vector3ub previousColor(0, 0, 0);
    for (size_t i = 1; i < points.size(); ++i) {
      const Vector3ub color = line->points[pointColor[i]].color;
      // ring of points[i - 1] (the "b" ring of this segment)
      unsigned int bStart;
      if (i > 1 && color == previousColor)
        bStart = previousRing;
      else
        bStart = emitRing(points[i - 1], color);
      // ring of points[i] (the "a" ring of this segment)
      const unsigned int aStart = emitRing(points[i], color);
      previousRing = aStart;
      previousColor = color;

      for (size_t j = 0; j < resolution; ++j) {
        const auto r1 = static_cast<unsigned int>(j);
        const auto r2 =
          static_cast<unsigned int>(j != 0 ? j - 1 : resolution - 1);
        indices.push_back(aStart + r1);
        indices.push_back(bStart + r1);
        indices.push_back(aStart + r2);

        indices.push_back(aStart + r2);
        indices.push_back(bStart + r1);
        indices.push_back(bStart + r2);
      }
    }
  }
}

void CurveGeometry::update(int index)
{
  Line* line = m_lines[index];
  line->numberOfVertices = 0;
  line->numberOfIndices = 0;

  // The pure-CPU geometry lives in tessellate(); only the GL upload is here.
  std::vector<ColorNormalVertex> vertices;
  std::vector<unsigned int> indices;
  tessellate(static_cast<size_t>(index), vertices, indices);

  if (vertices.empty()) {
    line->dirty = false;
    return;
  }

  line->vbo.upload(vertices, BufferObject::ArrayBuffer);
  if (!indices.empty()) {
    line->ibo.upload(indices, BufferObject::ElementArrayBuffer);
  }

  // Set up VAO with vertex attribute bindings (OpenGL 4.0 core profile)
  line->vao.bind();
  line->vbo.bind();
  if (!indices.empty()) {
    line->ibo.bind();
  } else {
    line->ibo.release();
  }

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

  line->vao.release();

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
      cout << shaderInfo.vertexShader.error() << '\n';
    if (!shaderInfo.fragmentShader.compile())
      cout << shaderInfo.fragmentShader.error() << '\n';
    shaderInfo.program.attachShader(shaderInfo.vertexShader);
    shaderInfo.program.attachShader(shaderInfo.fragmentShader);
    if (!shaderInfo.program.link())
      cout << shaderInfo.program.error() << '\n';
  }
}

void CurveGeometry::processShaderError(bool error)
{
  if (error) {
    cout << m_shaderInfo.program.error() << '\n';
  }
}

void CurveGeometry::render(const Camera& camera)
{
  if (m_dirty) {
    checkShaderInfo(m_shaderInfo, cylinders_fs, cylinders_vs);
    m_dirty = false;
  }

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

    // Bind the VAO (captures all vertex attribute state)
    line->vao.bind();

    if (line->numberOfVertices == 0) {
      line->vao.release();
      continue;
    }

    if (line->flat && m_canBeFlat) {
      glLineWidth(-line->radius);
      glDrawArrays(GL_LINE_STRIP, 0,
                   static_cast<GLsizei>(line->numberOfVertices));
    } else if (line->numberOfIndices > 0) {
      glDrawRangeElements(GL_TRIANGLES, 0,
                          static_cast<GLuint>(line->numberOfVertices - 1),
                          static_cast<GLsizei>(line->numberOfIndices),
                          GL_UNSIGNED_INT, reinterpret_cast<const GLvoid*>(0));
    }
    line->vao.release();
  }
  m_shaderInfo.program.release();
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
  m_lines[m_indexMap[group]]->add(Point(pos, color, id));
}

Array<Identifier> CurveGeometry::areaHits(const Frustrum& f) const
{
  Array<Identifier> result;
  // Check for intersection.
  for (const auto& line : m_lines) {
    size_t skip = 0;
    std::queue<size_t> previous;
    for (const auto& point : line->points) {
      previous.push(point.id);
      if (skip < 2) {
        ++skip;
        continue;
      }
      int in = 0;
      for (; in < 4; ++in) {
        float dist = (point.pos - f.points[2 * in]).dot(f.planes[in]);
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

} // namespace Avogadro::Rendering
