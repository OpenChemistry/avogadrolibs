/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cylindergeometry.h"

#include "camera.h"
#include "scene.h"
#include "visitor.h"

#include "bufferobject.h"
#include "vertexarrayobject.h"

#include "rendercontext_p.h"
#include "shaderprogram.h"

#include "avogadrogl.h"

#include <avogadro/core/matrix.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <iostream>
#include <type_traits>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

// m_cylinders is uploaded as the per-instance buffer, so the layout of
// CylinderColor is a contract with cylinders_vs.glsl. The two colors are
// bytes 28..33 and the shader reads them as two 4-byte aligned ubyte x 4
// attributes at offsets 28 and 32.
static_assert(std::is_standard_layout_v<CylinderColor>,
              "CylinderColor is uploaded to the GPU as is");
static_assert(sizeof(CylinderColor) == 36, "CylinderColor must be 36 bytes");
static_assert(offsetof(CylinderColor, end1) == 0, "end1 offset");
static_assert(offsetof(CylinderColor, end2) == 12, "end2 offset");
static_assert(offsetof(CylinderColor, radius) == 24, "radius offset");
static_assert(offsetof(CylinderColor, color) == 28, "color offset");
static_assert(offsetof(CylinderColor, color2) == 31, "color2 offset");

namespace {
constexpr unsigned int tubeSides = 8;
constexpr unsigned int tubeIndexCount = 6 * tubeSides;
constexpr int end1Offset = static_cast<int>(offsetof(CylinderColor, end1));
constexpr int end2Offset = static_cast<int>(offsetof(CylinderColor, end2));
constexpr int radiusOffset = static_cast<int>(offsetof(CylinderColor, radius));
constexpr int colorsAOffset = static_cast<int>(offsetof(CylinderColor, color));
constexpr int colorsBOffset = colorsAOffset + 4;
static_assert(colorsBOffset + 4 <= static_cast<int>(sizeof(CylinderColor)),
              "colorsB must stay inside one instance");
} // namespace

class CylinderGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;
  VertexArrayObject vao;
  ContextStamp contextStamp;

  size_t numberOfInstances = 0;
};

CylinderGeometry::CylinderGeometry() : m_dirty(false), d(new Private)
{
  setRenderPass(SolidPass);
}

CylinderGeometry::CylinderGeometry(const CylinderGeometry& other)
  : Drawable(other), m_cylinders(other.m_cylinders), m_indices(other.m_indices),
    m_indexMap(other.m_indexMap), m_dirty(true), d(new Private)
{
  setRenderPass(SolidPass);
}

CylinderGeometry::~CylinderGeometry()
{
  delete d;
}

void CylinderGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

// render() no longer calls this: the tube is built in cylinders_vs.glsl. This
// is the CPU reference for that construction (and what tests and exporters
// can still use), so keep the two in step.
void CylinderGeometry::tessellate(std::vector<ColorNormalVertex>& vertices,
                                  std::vector<unsigned int>& indices) const
{
  // Set some defaults for our cylinders.
  constexpr unsigned int resolution = 8; // points per circle
  constexpr double resolutionRadians =
    2.0 * M_PI / static_cast<double>(resolution);

  // cos(j * theta) and sin(j * theta), shared by every cylinder.
  float cosines[resolution];
  float sines[resolution];
  for (unsigned int j = 0; j < resolution; ++j) {
    cosines[j] = static_cast<float>(std::cos(j * resolutionRadians));
    sines[j] = static_cast<float>(std::sin(j * resolutionRadians));
  }

  const size_t count = std::min(m_indices.size(), m_cylinders.size());
  vertices.clear();
  indices.clear();
  // 2 vertices per point on the circle; 2 triangles per segment.
  vertices.reserve(count * 2 * resolution);
  indices.reserve(count * 6 * resolution);

  for (size_t i = 0; i < count; ++i) {
    const CylinderColor& cylinder = m_cylinders[i];
    const Vector3f& position1 = cylinder.end1;
    const Vector3f& position2 = cylinder.end2;
    const Vector3f direction = (position2 - position1).normalized();
    const float radius = cylinder.radius;

    // Rotating u about the unit vector d by j * theta (Rodrigues, with
    // d . u == 0) gives cos(j theta) u + sin(j theta) (d x u).
    const Vector3f u = direction.unitOrthogonal() * radius;
    const Vector3f w = direction.cross(u);

    // Cylinder
    ColorNormalVertex vert(cylinder.color, -direction, position1);
    ColorNormalVertex vert2(cylinder.color2, -direction, position1);
    const auto tubeStart = static_cast<unsigned int>(vertices.size());
    for (unsigned int j = 0; j < resolution; ++j) {
      const Vector3f radial = cosines[j] * u + sines[j] * w;
      vert.normal = radial;
      vert.vertex = position1 + radial;
      vertices.push_back(vert);
      vert2.normal = vert.normal;
      vert2.vertex = position2 + radial;
      vertices.push_back(vert2);
    }
    // Now to stitch it together.
    for (unsigned int j = 0; j < resolution; ++j) {
      unsigned int r1 = j + j;
      unsigned int r2 = (j != 0 ? r1 : resolution + resolution) - 2;
      indices.push_back(tubeStart + r1);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2);

      indices.push_back(tubeStart + r2);
      indices.push_back(tubeStart + r1 + 1);
      indices.push_back(tubeStart + r2 + 1);
    }
  }
}

void CylinderGeometry::update()
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  // The program must exist before VAO setup since we need it for attribute
  // setup.
  FallbackRenderContext fallbackContext;
  ShaderProgram* program = RenderContext::currentProgram(ShaderId::Cylinders);
  if (program == nullptr)
    return;

  if (d->contextStamp.forgetIfReplaced(d->vbo, d->ibo, d->vao))
    m_dirty = true;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    // The per-instance data is m_cylinders itself: no CPU vertex build.
    if (!d->vbo.upload(m_cylinders, BufferObject::ArrayBuffer))
      cout << d->vbo.error() << '\n';

    // Every cylinder draws the same 8-sided tube, so this never changes.
    if (!d->ibo.ready()) {
      std::vector<unsigned int> tubeIndices;
      tubeIndices.reserve(tubeIndexCount);
      for (unsigned int j = 0; j < tubeSides; ++j) {
        unsigned int r1 = j + j;
        unsigned int r2 = (j != 0 ? r1 : tubeSides + tubeSides) - 2;
        tubeIndices.push_back(r1);
        tubeIndices.push_back(r1 + 1);
        tubeIndices.push_back(r2);

        tubeIndices.push_back(r2);
        tubeIndices.push_back(r1 + 1);
        tubeIndices.push_back(r2 + 1);
      }
      if (!d->ibo.upload(tubeIndices, BufferObject::ElementArrayBuffer))
        cout << d->ibo.error() << '\n';
    }

    // Set up VAO with vertex attribute bindings (OpenGL 4.0 core profile)
    // Check bind() return values - if binding fails (e.g., no GL context),
    // early-return without clearing m_dirty so geometry will be retried later.
    if (!d->vao.bind()) {
      cout << "CylinderGeometry: VAO bind failed" << '\n';
      return;
    }
    if (!d->vbo.bind()) {
      cout << "CylinderGeometry: VBO bind failed" << '\n';
      d->vao.release();
      return;
    }
    if (!d->ibo.bind()) {
      cout << "CylinderGeometry: IBO bind failed" << '\n';
      d->vao.release();
      return;
    }

    // All attributes advance once per cylinder (instance).
    const auto stride = sizeof(CylinderColor);
    struct Attribute
    {
      const char* name;
      int offset;
      Avogadro::Type type;
      int size;
      ShaderProgram::NormalizeOption normalize;
    };
    const Attribute attributes[] = {
      { "end1", end1Offset, FloatType, 3, ShaderProgram::NoNormalize },
      { "end2", end2Offset, FloatType, 3, ShaderProgram::NoNormalize },
      { "cylRadius", radiusOffset, FloatType, 1, ShaderProgram::NoNormalize },
      { "colorsA", colorsAOffset, UCharType, 4, ShaderProgram::Normalize },
      { "colorsB", colorsBOffset, UCharType, 4, ShaderProgram::Normalize }
    };
    for (const Attribute& attribute : attributes) {
      if (!program->enableAttributeArray(attribute.name))
        cout << program->error() << '\n';
      if (!program->useAttributeArray(attribute.name, attribute.offset, stride,
                                      attribute.type, attribute.size,
                                      attribute.normalize)) {
        cout << program->error() << '\n';
      }
      if (!program->setAttributeDivisor(attribute.name, 1))
        cout << program->error() << '\n';
    }

    d->vao.release();

    d->numberOfInstances = std::min(m_indices.size(), m_cylinders.size());

    m_dirty = false;
  }
}

void CylinderGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  FallbackRenderContext fallbackContext;

  // Prepare the VBOs, IBOs, VAO, and shader program if necessary.
  update();

  ShaderProgram* program = RenderContext::currentProgram(ShaderId::Cylinders);
  if (program == nullptr)
    return;

  if (!program->bind())
    cout << program->error() << '\n';

  // Bind the VAO (captures all vertex attribute state)
  // If bind fails (e.g., no GL context), skip rendering to avoid GL errors.
  if (!d->vao.bind()) {
    program->release();
    return;
  }

  RenderContext::useCamera(camera);
  if (!program->setUniformValue("opacity", m_opacity)) {
    cout << program->error() << '\n';
  }

  // Render the loaded cylinders using the shader and VAO.
  if (d->numberOfInstances > 0) {
    glDrawElementsInstanced(GL_TRIANGLES, tubeIndexCount, GL_UNSIGNED_INT,
                            nullptr,
                            static_cast<GLsizei>(d->numberOfInstances));
  }

  d->vao.release();
  program->release();
}

std::multimap<float, Identifier> CylinderGeometry::hits(
  const Vector3f& rayOrigin, const Vector3f& rayEnd,
  const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> result;

  for (size_t i = 0; i < m_cylinders.size(); ++i) {
    const CylinderColor& cylinder = m_cylinders[i];

    // Check for cylinder intersection with the ray.
    Vector3f ao = rayOrigin - cylinder.end1;
    Vector3f ab = cylinder.end2 - cylinder.end1;
    Vector3f aoxab = ao.cross(ab);
    Vector3f vxab = rayDirection.cross(ab);

    float A = vxab.dot(vxab);
    float B = 2.0f * vxab.dot(aoxab);
    float C =
      aoxab.dot(aoxab) - ab.dot(ab) * (cylinder.radius * cylinder.radius);
    float D = B * B - 4.0f * A * C;

    // no intersection
    if (D < 0.0f)
      continue;

    float t = std::min((-B + std::sqrt(D)) / (2.0f * A),
                       (-B - std::sqrt(D)) / (2.0f * A));

    Vector3f ip = rayOrigin + (rayDirection * t);
    Vector3f ip1 = ip - cylinder.end1;
    Vector3f ip2 = ip - (cylinder.end1 + ab);

    // intersection below base or above top of the cylinder
    if (ip1.dot(ab) < 0.0f || ip2.dot(ab) > 0.0f)
      continue;

    // Test for clipping
    Vector3f distance = ip - rayOrigin;
    if (distance.dot(rayDirection) < 0.0f ||
        (ip - rayEnd).dot(rayDirection) > 0.0f)
      continue;

    Identifier id;
    id.molecule = m_identifier.molecule;
    id.type = m_identifier.type;
    id.index = i;
    // Cylinders added without an explicit index have no entry (or the
    // MaxIndex sentinel): they are identified by their position.
    if (i < m_indexMap.size() && m_indexMap[i] != MaxIndex)
      id.index = m_indexMap[i];
    if (id.type != InvalidType) {
      float depth = distance.norm();
      result.insert(std::pair<float, Identifier>(depth, id));
    }
  }

  return result;
}

void CylinderGeometry::addCylinder(const Vector3f& pos1, const Vector3f& pos2,
                                   float radius, const Vector3ub& color)
{
  addCylinder(pos1, pos2, radius, color, color);
}

void CylinderGeometry::addCylinder(const Vector3f& pos1, const Vector3f& pos2,
                                   float radius, const Vector3ub& colorStart,
                                   const Vector3ub& colorEnd)
{
  m_dirty = true;
  m_cylinders.emplace_back(pos1, pos2, radius, colorStart, colorEnd);
  m_indices.push_back(m_indices.size());
}

void CylinderGeometry::addCylinder(const Vector3f& pos1, const Vector3f& pos2,
                                   float radius, const Vector3ub& color,
                                   size_t index)
{
  setIndex(m_cylinders.size(), index);
  addCylinder(pos1, pos2, radius, color, color);
}

void CylinderGeometry::addCylinder(const Vector3f& pos1, const Vector3f& pos2,
                                   float radius, const Vector3ub& colorStart,
                                   const Vector3ub& colorEnd, size_t index)
{
  setIndex(m_cylinders.size(), index);
  addCylinder(pos1, pos2, radius, colorStart, colorEnd);
}

void CylinderGeometry::setIndex(size_t cylinder, size_t index)
{
  if (m_indexMap.size() <= cylinder)
    m_indexMap.resize(cylinder + 1, MaxIndex);
  m_indexMap[cylinder] = index;
}

void CylinderGeometry::clear()
{
  m_cylinders.clear();
  m_indices.clear();
  m_indexMap.clear();
}

} // namespace Avogadro::Rendering
