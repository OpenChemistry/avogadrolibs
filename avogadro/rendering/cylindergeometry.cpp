/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cylindergeometry.h"

#include "camera.h"
#include "scene.h"
#include "visitor.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

namespace {
#include "cylinders_fs.h"
#include "cylinders_vs.h"
} // namespace

#include "avogadrogl.h"

#include <avogadro/core/matrix.h>

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

class CylinderGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;

  inline static Shader* vertexShader = nullptr;
  inline static Shader* fragmentShader = nullptr;
  inline static ShaderProgram* program = nullptr;

  size_t numberOfVertices;
  size_t numberOfIndices;
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

void CylinderGeometry::update()
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    // Set some defaults for our cylinders.
    const unsigned int resolution = 8; // points per circle
    const float resolutionRadians =
      2.0f * static_cast<float>(M_PI) / static_cast<float>(resolution);
    std::vector<Vector3f> radials;
    radials.reserve(resolution);

    std::vector<unsigned int> cylinderIndices;
    std::vector<ColorNormalVertex> cylinderVertices;
    // cylinderIndices.reserve(m_indices.size() * 4);
    // cylinderVertices.reserve(m_cylinders.size() * 4);

    auto itIndex = m_indices.begin();
    auto itCylinder = m_cylinders.begin();

    for (unsigned int i = 0;
         itIndex != m_indices.end() && itCylinder != m_cylinders.end();
         ++i, ++itIndex, ++itCylinder) {

      const Vector3f& position1 = itCylinder->end1;
      const Vector3f& position2 = itCylinder->end2;
      const Vector3f direction = (position2 - position1).normalized();
      float radius = itCylinder->radius;

      // Generate the radial vectors
      Vector3f radialVec = direction.unitOrthogonal() * radius;
      Eigen::AngleAxisf transform(resolutionRadians, direction);
      radials.clear();
      for (unsigned int j = 0; j < resolution; ++j) {
        radials.push_back(radialVec);
        radialVec = transform * radialVec;
      }

      // Cylinder
      ColorNormalVertex vert(itCylinder->color, -direction, position1);
      ColorNormalVertex vert2(itCylinder->color2, -direction, position1);
      const auto tubeStart = static_cast<unsigned int>(cylinderVertices.size());
      for (auto& radial : radials) {
        vert.normal = radial;
        vert.vertex = position1 + radial;
        cylinderVertices.push_back(vert);
        vert2.normal = vert.normal;
        vert2.vertex = position2 + radial;
        cylinderVertices.push_back(vert2);
      }
      // Now to stitch it together.
      for (unsigned int j = 0; j < resolution; ++j) {
        unsigned int r1 = j + j;
        unsigned int r2 = (j != 0 ? r1 : resolution + resolution) - 2;
        cylinderIndices.push_back(tubeStart + r1);
        cylinderIndices.push_back(tubeStart + r1 + 1);
        cylinderIndices.push_back(tubeStart + r2);

        cylinderIndices.push_back(tubeStart + r2);
        cylinderIndices.push_back(tubeStart + r1 + 1);
        cylinderIndices.push_back(tubeStart + r2 + 1);
      }
    }

    d->vbo.upload(cylinderVertices, BufferObject::ArrayBuffer);
    d->ibo.upload(cylinderIndices, BufferObject::ElementArrayBuffer);
    d->numberOfVertices = cylinderVertices.size();
    d->numberOfIndices = cylinderIndices.size();

    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader == nullptr) {
    d->vertexShader = new Shader;
    d->vertexShader->setType(Shader::Vertex);
    d->vertexShader->setSource(cylinders_vs);
    d->fragmentShader = new Shader;
    d->fragmentShader->setType(Shader::Fragment);
    d->fragmentShader->setSource(cylinders_fs);
    if (!d->vertexShader->compile())
      cout << d->vertexShader->error() << endl;
    if (!d->fragmentShader->compile())
      cout << d->fragmentShader->error() << endl;

    if (d->program == nullptr)
      d->program = new ShaderProgram;

    d->program->attachShader(*d->vertexShader);
    d->program->attachShader(*d->fragmentShader);
    if (!d->program->link())
      cout << d->program->error() << endl;
  }
}

void CylinderGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  if (!d->program->bind())
    cout << d->program->error() << endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!d->program->enableAttributeArray("vertex"))
    cout << d->program->error() << endl;
  if (!d->program->useAttributeArray(
        "vertex", ColorNormalVertex::vertexOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize)) {
    cout << d->program->error() << endl;
  }
  if (!d->program->enableAttributeArray("color"))
    cout << d->program->error() << endl;
  if (!d->program->useAttributeArray("color", ColorNormalVertex::colorOffset(),
                                     sizeof(ColorNormalVertex), UCharType, 3,
                                     ShaderProgram::Normalize)) {
    cout << d->program->error() << endl;
  }
  if (!d->program->enableAttributeArray("normal"))
    cout << d->program->error() << endl;
  if (!d->program->useAttributeArray(
        "normal", ColorNormalVertex::normalOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize)) {
    cout << d->program->error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program->setUniformValue("modelView", camera.modelView().matrix())) {
    cout << d->program->error() << endl;
  }
  if (!d->program->setUniformValue("projection",
                                   camera.projection().matrix())) {
    cout << d->program->error() << endl;
  }
  if (!d->program->setUniformValue("opacity", m_opacity)) {
    cout << d->program->error() << endl;
  }
  Matrix3f normalMatrix = camera.modelView().linear().inverse().transpose();
  if (!d->program->setUniformValue("normalMatrix", normalMatrix))
    std::cout << d->program->error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0, static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vbo.release();
  d->ibo.release();

  d->program->disableAttributeArray("vector");
  d->program->disableAttributeArray("color");
  d->program->disableAttributeArray("normal");

  d->program->release();
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
    if (m_indexMap.size())
      id.index = m_indexMap.find(i)->second;
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
  m_indexMap[m_cylinders.size()] = index;
  addCylinder(pos1, pos2, radius, color, color);
}

void CylinderGeometry::addCylinder(const Vector3f& pos1, const Vector3f& pos2,
                                   float radius, const Vector3ub& colorStart,
                                   const Vector3ub& colorEnd, size_t index)
{
  m_indexMap[m_cylinders.size()] = index;
  addCylinder(pos1, pos2, radius, colorStart, colorEnd);
}

void CylinderGeometry::clear()
{
  m_cylinders.clear();
  m_indices.clear();
  m_indexMap.clear();
}

} // namespace Avogadro::Rendering
