/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "arrowgeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "packedvertex.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <Eigen/Geometry>

#include <cmath>
#include <iostream>
#include <limits>

namespace {
// Use the mesh shaders for proper lighting
#include "mesh_fs.h"
#include "mesh_vs.h"

const float M_PI_F = 3.14159265358979323846f;
} // namespace

using Avogadro::FloatType;
using Avogadro::UCharType;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Rendering::PackedVertex;
using Avogadro::Rendering::ShaderProgram;

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

class ArrowGeometry::Private
{
public:
  Private() : numberOfVertices(0), numberOfIndices(0) {}

  BufferObject vbo;
  BufferObject ibo;

  inline static Shader* vertexShader = nullptr;
  inline static Shader* fragmentShader = nullptr;
  inline static ShaderProgram* program = nullptr;

  Core::Array<PackedVertex> meshVertices;
  Core::Array<unsigned int> meshIndices;

  size_t numberOfVertices;
  size_t numberOfIndices;
};

ArrowGeometry::ArrowGeometry()
  : m_color(0, 255, 0), m_radiusScale(1.0f), m_dirty(false), d(new Private)
{
}

ArrowGeometry::ArrowGeometry(const ArrowGeometry& other)
  : Drawable(other), m_arrows(other.m_arrows), m_color(other.m_color),
    m_radiusScale(other.m_radiusScale), m_dirty(true), d(new Private)
{
}

ArrowGeometry::~ArrowGeometry()
{
  delete d;
}

void ArrowGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

namespace {

/**
 * Generate arrow geometry (cylinder shaft + cone head) for a single arrow.
 * Adapted from overlayaxes plugin.
 *
 * @param origin Start point of the arrow
 * @param target End point of the arrow (tip of arrowhead)
 * @param color The arrow color
 * @param radiusScale Scale factor for arrow radii (1.0 = default)
 * @param vertices Output vertex array
 * @param indices Output index array
 * @param baseOffset Starting index offset for this arrow's vertices
 */
void generateArrowGeometry(const Vector3f& origin, const Vector3f& target,
                           const Vector4ub& color, float radiusScale,
                           Core::Array<PackedVertex>& vertices,
                           Core::Array<unsigned int>& indices,
                           unsigned int baseOffset)
{
  Vector3f arrowVec = target - origin;
  float totalLength = arrowVec.norm();
  if (totalLength < 1e-6f)
    return;

  Vector3f axis = arrowVec.normalized();

  // Number of angular samples for cylinder/cone
  const unsigned int res = 12;
  const auto resf = static_cast<float>(res);

  // Proportions: 80% cylinder, 20% cone head
  const float cylLength = totalLength * 0.8f;
  const float coneLength = totalLength * 0.2f;

  // Radii proportional to arrow length, with optional scale factor
  const float cylRadius = totalLength * 0.02f * radiusScale;
  const float coneRadius = totalLength * 0.05f * radiusScale;

  // Key vectors
  const Vector3f cylEnd = origin + axis * cylLength;
  const Vector3f radialUnit = axis.unitOrthogonal();

  // Index offsets within this arrow's vertex set
  const unsigned int coneBaseOffset = 0;
  const unsigned int coneBaseRadialsOffset = coneBaseOffset + 1;
  const unsigned int coneSideRadialsOffset = coneBaseRadialsOffset + res;
  const unsigned int coneTipsOffset = coneSideRadialsOffset + res;
  const unsigned int cylBaseRadialsOffset = coneTipsOffset + res;
  const unsigned int cylTopRadialsOffset = cylBaseRadialsOffset + res;
  const unsigned int numVertices = cylTopRadialsOffset + res;

  // Allocate temporary vertex/normal arrays
  Core::Array<Vector3f> verts(numVertices);
  Core::Array<Vector3f> norms(numVertices);

  // Cone base center point
  verts[coneBaseOffset] = cylEnd;
  norms[coneBaseOffset] = -axis;

  // Create radial transform for stepping around the circle
  Eigen::Affine3f xform(Eigen::AngleAxisf(2.f * M_PI_F / resf, axis));
  Vector3f radial = radialUnit;

  // Build vertex list
  for (unsigned int i = 0; i < res; ++i) {
    Vector3f coneRadial = cylEnd + (radial * coneRadius);

    // Cone side normal calculation
    Vector3f coneVec = axis * coneLength;
    Vector3f coneSideNormal = -(coneVec.cross(radial * coneRadius))
                                 .cross(coneVec - radial * coneRadius)
                                 .normalized();

    // Cone base radials (facing back)
    verts[coneBaseRadialsOffset + i] = coneRadial;
    norms[coneBaseRadialsOffset + i] = -axis;

    // Cone side radials
    verts[coneSideRadialsOffset + i] = coneRadial;
    norms[coneSideRadialsOffset + i] = coneSideNormal;

    // Cylinder vertices
    Vector3f cylRadial = radial * cylRadius;
    verts[cylBaseRadialsOffset + i] = origin + cylRadial;
    norms[cylBaseRadialsOffset + i] = radial;

    verts[cylTopRadialsOffset + i] = cylEnd + cylRadial;
    norms[cylTopRadialsOffset + i] = radial;

    radial = xform * radial;
  }

  // Cone tip normals (average of adjacent side normals)
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int ind1 = coneSideRadialsOffset + i;
    unsigned int ind2 = coneSideRadialsOffset + ((i + 1) % res);
    verts[coneTipsOffset + i] = target;
    norms[coneTipsOffset + i] = (norms[ind1] + norms[ind2]).normalized();
  }

  // Add vertices to output array
  size_t vertexStart = vertices.size();
  for (unsigned int i = 0; i < numVertices; ++i) {
    vertices.push_back(PackedVertex(color, norms[i], verts[i]));
  }

  // Build triangle indices
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int i2 = (i + 1) % res;

    // Cone sides
    indices.push_back(baseOffset + coneTipsOffset + i);
    indices.push_back(baseOffset + coneSideRadialsOffset + i);
    indices.push_back(baseOffset + coneSideRadialsOffset + i2);

    // Cone base
    indices.push_back(baseOffset + coneBaseRadialsOffset + i);
    indices.push_back(baseOffset + coneBaseOffset);
    indices.push_back(baseOffset + coneBaseRadialsOffset + i2);

    // Cylinder side quad (2 triangles)
    indices.push_back(baseOffset + cylTopRadialsOffset + i);
    indices.push_back(baseOffset + cylBaseRadialsOffset + i);
    indices.push_back(baseOffset + cylTopRadialsOffset + i2);

    indices.push_back(baseOffset + cylBaseRadialsOffset + i);
    indices.push_back(baseOffset + cylTopRadialsOffset + i2);
    indices.push_back(baseOffset + cylBaseRadialsOffset + i2);
  }
}

} // anonymous namespace

void ArrowGeometry::update()
{
  if (m_arrows.empty())
    return;

  // Rebuild mesh geometry if dirty
  if (!d->vbo.ready() || m_dirty) {
    d->meshVertices.clear();
    d->meshIndices.clear();

    // Number of vertices per arrow (see generateArrowGeometry)
    const unsigned int res = 12;
    const unsigned int vertsPerArrow = 1 + res * 5; // cone base + 5 rings

    // Reserve space for all arrows
    d->meshVertices.reserve(m_arrows.size() * vertsPerArrow);
    d->meshIndices.reserve(m_arrows.size() * res * 4 * 3); // 4 tris * 3 indices

    unsigned int baseOffset = 0;
    for (const auto& arrow : m_arrows) {
      Vector4ub color4(arrow.color[0], arrow.color[1], arrow.color[2], 255);
      generateArrowGeometry(arrow.start, arrow.end, color4, m_radiusScale,
                            d->meshVertices, d->meshIndices, baseOffset);
      baseOffset = static_cast<unsigned int>(d->meshVertices.size());
    }

    // Upload to GPU
    if (!d->meshVertices.empty()) {
      d->vbo.upload(d->meshVertices, BufferObject::ArrayBuffer);
      d->ibo.upload(d->meshIndices, BufferObject::ElementArrayBuffer);
    }
    // update these even if empty (i.e. avoid stale data)
    d->numberOfVertices = d->meshVertices.size();
    d->numberOfIndices = d->meshIndices.size();

    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader == nullptr) {
    d->vertexShader = new Shader;
    d->vertexShader->setType(Shader::Vertex);
    d->vertexShader->setSource(mesh_vs);

    d->fragmentShader = new Shader;
    d->fragmentShader->setType(Shader::Fragment);
    d->fragmentShader->setSource(mesh_fs);

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

void ArrowGeometry::render(const Camera& camera)
{
  if (m_arrows.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  if (d->numberOfVertices == 0 || d->numberOfIndices == 0)
    return;

  ShaderProgram* program = d->program;

  if (!program->bind())
    cout << program->error() << endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!program->enableAttributeArray("vertex"))
    cout << program->error() << endl;
  if (!program->useAttributeArray("vertex", PackedVertex::vertexOffset(),
                                  sizeof(PackedVertex), FloatType, 3,
                                  ShaderProgram::NoNormalize)) {
    cout << program->error() << endl;
  }
  if (!program->enableAttributeArray("color"))
    cout << program->error() << endl;
  if (!program->useAttributeArray("color", PackedVertex::colorOffset(),
                                  sizeof(PackedVertex), UCharType, 4,
                                  ShaderProgram::Normalize)) {
    cout << program->error() << endl;
  }
  if (!program->enableAttributeArray("normal"))
    cout << program->error() << endl;
  if (!program->useAttributeArray("normal", PackedVertex::normalOffset(),
                                  sizeof(PackedVertex), FloatType, 3,
                                  ShaderProgram::NoNormalize)) {
    cout << program->error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!program->setUniformValue("modelView", camera.modelView().matrix())) {
    cout << program->error() << endl;
  }
  if (!program->setUniformValue("projection", camera.projection().matrix())) {
    cout << program->error() << endl;
  }
  Matrix3f normalMatrix = camera.modelView().linear().inverse().transpose();
  if (!program->setUniformValue("normalMatrix", normalMatrix))
    cout << program->error() << endl;

  // Render using the shader and bound VBOs.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices - 1),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vbo.release();
  d->ibo.release();

  program->disableAttributeArray("vertex");
  program->disableAttributeArray("color");
  program->disableAttributeArray("normal");

  program->release();
}

void ArrowGeometry::clear()
{
  m_arrows.clear();
  d->meshVertices.clear();
  d->meshIndices.clear();
  m_dirty = true;
}

void ArrowGeometry::addSingleArrow(const Vector3f& pos1, const Vector3f& pos2,
                                   const Vector3ub& color)
{
  m_arrows.push_back(Arrow(pos1, pos2, color));
  m_dirty = true;
}

void ArrowGeometry::addSingleArrow(const Vector3f& pos1, const Vector3f& pos2)
{
  addSingleArrow(pos1, pos2, m_color);
}

} // namespace Avogadro::Rendering
