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
  return flat ? 1u : sidesOr(kDefaultTubeSides);
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

// What sample q is, for a line of n control points sampled `perSegment` times
// per segment. See CurveGeometry::computeSegmentPoint() for who owns what.
struct SamplePosition
{
  size_t segment;    // of the curve
  float f;           // within it, [0, 1)
  size_t owner;      // control point passed to computeScale()
  float ownerT;      // position within that control point's stretch, [0, 1]
  size_t colorOwner; // control point whose colour the strip ending here uses
};

SamplePosition samplePosition(size_t q, size_t perSegment, size_t n)
{
  SamplePosition s;
  s.segment = q / perSegment;
  const size_t j = q % perSegment;
  s.f = static_cast<float>(j) / static_cast<float>(perSegment);
  if (s.segment >= n) { // the end of the last segment
    s.owner = s.colorOwner = n - 1;
    s.ownerT = 1.0f;
  } else {
    s.owner = s.segment;
    s.ownerT = s.f;
    // the first sample of a segment ends the previous one
    s.colorOwner = j > 0 || s.segment == 0 ? s.segment : s.segment - 1;
  }
  return s;
}

// A frame along the curve and the control point whose colour it carries.
struct CurveFrame
{
  Eigen::Affine3f transform;
  unsigned int colorIndex;
};

// The frame for a step along `tangent`: the columns are the broad axis, the
// tangent and the third axis. The broad axis turns as little as possible from
// that of the previous frame (which carries its scale), by flipping it if it
// is more than 90 degrees away and by bisecting if it is still more than 25
// degrees away. Returns false if the angle is not a number.
bool nextFrame(const Eigen::Affine3f* previous, const Vector3f& tangent,
               Eigen::Matrix3f& m)
{
  static const float cosMaxTurn = std::cos(25.0f * DEG_TO_RAD_F);
  m.col(1) = tangent.normalized();
  m.col(0) = m.col(1).unitOrthogonal() * -1.0f;
  if (previous != nullptr) {
    const Vector3f previousAxis = previous->linear().col(0);
    float angle = previousAxis.dot(m.col(0));
    if (std::isnan(angle))
      return false;
    // if angle > 90 flip it
    if (angle <= 0.0f)
      m.col(0) *= -1.0f;
    // the previous axis has the length of its scale; this one is a unit vector
    const float scale = previousAxis.norm();
    float cosAngle =
      std::clamp(previousAxis.dot(m.col(0)) / scale, -1.0f, 1.0f);
    // if the angle is > 25 degrees get the bisector
    int maxIter = 10;
    while (cosAngle < cosMaxTurn && --maxIter > 0) {
      m.col(0) = (m.col(0) + previousAxis).normalized();
      cosAngle = std::clamp(previousAxis.dot(m.col(0)) / scale, -1.0f, 1.0f);
    }
  }
  m.col(2) = m.col(0).cross(m.col(1)) * -1.0f;
  return true;
}

} // namespace

float CurveGeometry::residueCoordinate(size_t segment, float f, size_t count)
{
  const size_t last = count > 0 ? count - 1 : 0;
  if (segment >= count)
    return static_cast<float>(last);
  if (segment == 0)
    return 0.5f * f;
  if (segment == last)
    return static_cast<float>(last) - 0.5f + 0.5f * f;
  return static_cast<float>(segment) - 0.5f + f;
}

size_t CurveGeometry::segmentsFor(bool flat) const
{
  const size_t base =
    m_segmentsPerResidue > 0 ? m_segmentsPerResidue : kDefaultSegments;
  // flat lines have always been sampled 4/3 as finely
  return flat ? flatSegmentsFor(base) : base;
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

  // Sample q of the curve gets a frame; the strip between frames i - 1 and i
  // takes the colour of frame i. The first frame looks towards the second
  // sample.
  const size_t totalSamples =
    qttyPoints >= 2 ? qttyPoints * lineResolution + 1 : 0;
  auto positionAt = [&](size_t q) {
    const SamplePosition s = samplePosition(q, lineResolution, qttyPoints);
    return computeSegmentPoint(s.segment, s.f, line->points);
  };

  std::vector<CurveFrame> frames;
  frames.reserve(totalSamples);
  Vector3f previous = Vector3f::Zero();
  const Vector3f first = totalSamples > 0 ? positionAt(0) : previous;
  const Vector3f second = totalSamples > 1 ? positionAt(1) : previous;
  bool nanDetected = false;
  for (size_t q = 0; q < totalSamples && !nanDetected; ++q) {
    const Vector3f p = q == 0 ? first : q == 1 ? second : positionAt(q);
    const Vector3f tangent = q > 0 ? p - previous : second - p;
    if (tangent.squaredNorm() < 1e-10f) {
      previous = p;
      continue;
    }
    Eigen::Matrix3f m;
    if (!nextFrame(frames.empty() ? nullptr : &frames.back().transform, tangent,
                   m)) {
      nanDetected = true;
      break;
    }
    const SamplePosition s = samplePosition(q, lineResolution, qttyPoints);
    Eigen::Affine3f affine;
    affine.translation() = p;
    affine.linear() = m;
    float r = !m_canBeFlat || !line->flat
                ? computeScale(s.owner, s.ownerT, line->radius)
                : 0.01f;
    affine.scale(r);
    frames.push_back({ affine, static_cast<unsigned int>(s.colorOwner) });
    previous = p;
  }

  if (frames.empty())
    return;

  if (line->flat && m_canBeFlat) {
    vertices.reserve(frames.size());

    for (const auto& frame : frames) {
      Vector3f normal = frame.transform.linear().col(0);
      if (normal.squaredNorm() < 1e-10f) {
        normal = Vector3f::UnitX();
      } else {
        normal.normalize();
      }
      vertices.emplace_back(line->points[frame.colorIndex].color, normal,
                            frame.transform.translation());
    }
  } else {
    const size_t resolution = circleResolution(line->flat);
    const size_t segmentCount = frames.size() > 1 ? frames.size() - 1 : 0;
    // Each ring is shared by the two segments that meet there; it is only
    // duplicated where the colour changes between consecutive segments.
    vertices.reserve(ringVertices(qttyPoints, lineResolution, resolution) +
                     resolution);
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
    for (size_t i = 1; i < frames.size(); ++i) {
      const Vector3ub color = line->points[frames[i].colorIndex].color;
      // ring of frames[i - 1] (the "b" ring of this segment)
      unsigned int bStart;
      if (i > 1 && color == previousColor)
        bStart = previousRing;
      else
        bStart = emitRing(frames[i - 1].transform, color);
      // ring of frames[i] (the "a" ring of this segment)
      const unsigned int aStart = emitRing(frames[i].transform, color);
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
