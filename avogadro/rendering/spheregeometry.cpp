/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spheregeometry.h"

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"
#include "vertexarrayobject.h"

#include "rendercontext_p.h"
#include "shaderprogram.h"

#include "visitor.h"

#include "avogadrogl.h"

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <type_traits>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

using Core::Array;

// m_spheres is uploaded as the per-instance buffer, so the layout of
// SphereColor is a contract with spheres_vs.glsl.
static_assert(std::is_standard_layout_v<SphereColor>,
              "SphereColor is uploaded to the GPU as is");
static_assert(sizeof(SphereColor) == 20, "SphereColor must be 20 bytes");
static_assert(offsetof(SphereColor, center) == 0, "center offset");
static_assert(offsetof(SphereColor, radius) == 12, "radius offset");
static_assert(offsetof(SphereColor, color) == 16, "color offset");

namespace {
constexpr int centerOffset = static_cast<int>(offsetof(SphereColor, center));
constexpr int radiusOffset = static_cast<int>(offsetof(SphereColor, radius));
constexpr int colorOffset = static_cast<int>(offsetof(SphereColor, color));
} // namespace

class SphereGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;
  VertexArrayObject vao;
  ContextStamp contextStamp;

  size_t numberOfInstances = 0;
};

SphereGeometry::SphereGeometry() : m_dirty(false), d(new Private)
{
  setRenderPass(SolidPass);
}

SphereGeometry::SphereGeometry(const SphereGeometry& other)
  : Drawable(other), m_spheres(other.m_spheres), m_indices(other.m_indices),
    m_dirty(true), d(new Private)
{
  setRenderPass(SolidPass);
}

SphereGeometry::~SphereGeometry()
{
  delete d;
}

void SphereGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void SphereGeometry::update()
{
  if (m_indices.empty() || m_spheres.empty())
    return;

  // The program must exist before VAO setup since we need it for attribute
  // setup.
  FallbackRenderContext fallbackContext;
  ShaderProgram* program = RenderContext::currentProgram(ShaderId::Spheres);
  if (program == nullptr)
    return;

  if (d->contextStamp.forgetIfReplaced(d->vbo, d->ibo, d->vao))
    m_dirty = true;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    // The per-instance data is m_spheres itself: no CPU vertex build.
    if (!d->vbo.upload(m_spheres, BufferObject::ArrayBuffer))
      cout << d->vbo.error() << '\n';

    // Every sphere draws the same quad, so this never changes.
    if (!d->ibo.ready()) {
      const std::vector<unsigned int> quadIndices = { 0, 1, 2, 3, 2, 1 };
      if (!d->ibo.upload(quadIndices, BufferObject::ElementArrayBuffer))
        cout << d->ibo.error() << '\n';
    }

    // Set up VAO with vertex attribute bindings (OpenGL 4.0 core profile)
    // Check bind() return values - if binding fails (e.g., no GL context),
    // early-return without clearing m_dirty so geometry will be retried later.
    if (!d->vao.bind()) {
      cout << "SphereGeometry: VAO bind failed" << '\n';
      return;
    }
    if (!d->vbo.bind()) {
      cout << "SphereGeometry: VBO bind failed" << '\n';
      d->vao.release();
      return;
    }
    if (!d->ibo.bind()) {
      cout << "SphereGeometry: IBO bind failed" << '\n';
      d->vao.release();
      return;
    }

    // The three attributes advance once per sphere (instance).
    const auto stride = sizeof(SphereColor);
    if (!program->enableAttributeArray("center"))
      cout << program->error() << '\n';
    if (!program->useAttributeArray("center", centerOffset, stride, FloatType,
                                    3, ShaderProgram::NoNormalize)) {
      cout << program->error() << '\n';
    }
    if (!program->setAttributeDivisor("center", 1))
      cout << program->error() << '\n';
    if (!program->enableAttributeArray("sphereRadius"))
      cout << program->error() << '\n';
    if (!program->useAttributeArray("sphereRadius", radiusOffset, stride,
                                    FloatType, 1, ShaderProgram::NoNormalize)) {
      cout << program->error() << '\n';
    }
    if (!program->setAttributeDivisor("sphereRadius", 1))
      cout << program->error() << '\n';
    if (!program->enableAttributeArray("color"))
      cout << program->error() << '\n';
    if (!program->useAttributeArray("color", colorOffset, stride, UCharType, 3,
                                    ShaderProgram::Normalize)) {
      cout << program->error() << '\n';
    }
    if (!program->setAttributeDivisor("color", 1))
      cout << program->error() << '\n';

    d->vao.release();

    d->numberOfInstances = std::min(m_indices.size(), m_spheres.size());

    m_dirty = false;
  }
}

void SphereGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_spheres.empty())
    return;

  FallbackRenderContext fallbackContext;

  // Prepare the VBOs, IBOs, VAO, and shader program if necessary.
  update();

  ShaderProgram* program = RenderContext::currentProgram(ShaderId::Spheres);
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

  // Render the loaded spheres using the shader and VAO.
  if (d->numberOfInstances > 0) {
    glDrawElementsInstanced(GL_TRIANGLES, 6, GL_UNSIGNED_INT, nullptr,
                            static_cast<GLsizei>(d->numberOfInstances));
  }

  d->vao.release();
  program->release();
}

std::multimap<float, Identifier> SphereGeometry::hits(
  const Vector3f& rayOrigin, const Vector3f& rayEnd,
  const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> result;

  // Check for intersection.
  for (size_t i = 0; i < m_spheres.size(); ++i) {
    const SphereColor& sphere = m_spheres[i];

    Vector3f distance = sphere.center - rayOrigin;
    float B = distance.dot(rayDirection);
    float C = distance.dot(distance) - (sphere.radius * sphere.radius);
    float D = B * B - C;

    // Test for intersection
    if (D < 0.0f)
      continue;

    // Test for clipping
    if (B < 0.0f || (sphere.center - rayEnd).dot(rayDirection) > 0.0f)
      continue;

    Identifier id;
    id.molecule = m_identifier.molecule;
    id.type = m_identifier.type;
    id.index = m_indices[i];
    if (id.type != InvalidType) {
      auto rootD = static_cast<float>(sqrt(D));
      float depth = std::min(std::abs(B + rootD), std::abs(B - rootD));
      result.insert(std::pair<float, Identifier>(depth, id));
    }
  }
  return result;
}

Array<Identifier> SphereGeometry::areaHits(const Frustrum& f) const
{
  Array<Identifier> result;

  // Check for intersection.
  for (size_t i = 0; i < m_spheres.size(); ++i) {
    const SphereColor& sphere = m_spheres[i];

    bool inside = true;
    for (int p = 0; p < 4; ++p) {
      // Distance from sphere center to plane (using any point on the plane)
      float dist = (sphere.center - f.points[2 * p]).dot(f.planes[p]);

      // If sphere center is outside this plane (positive distance)
      // Note: could also test dist > -sphere.radius for sphere-plane
      // intersection
      if (dist > 0.0f) {
        inside = false;
        break;
      }
    }

    if (inside) {
      Identifier id;
      id.molecule = m_identifier.molecule;
      id.type = m_identifier.type;
      id.index = m_indices[i];
      result.push_back(id);
    }
  }
  return result;
}

void SphereGeometry::addSphere(const Vector3f& position, const Vector3ub& color,
                               float radius, size_t index)
{
  m_dirty = true;
  m_spheres.push_back(SphereColor(position, radius, color));
  m_indices.push_back(index == MaxIndex ? m_indices.size() : index);
}

void SphereGeometry::clear()
{
  m_spheres.clear();
  m_indices.clear();
}

} // namespace Avogadro::Rendering
