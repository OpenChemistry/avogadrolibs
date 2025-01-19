/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "meshgeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <iostream>
#include <iterator>
#include <limits>

namespace {
#include "mesh_fs.h"
#include "mesh_opaque_fs.h"
#include "mesh_vs.h"
} // namespace

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

const unsigned int MeshGeometry::InvalidIndex =
  std::numeric_limits<unsigned int>::max();

class MeshGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;

  inline static Shader* vertexShader = nullptr;
  inline static Shader* fragmentShader = nullptr;
  inline static Shader* fragmentShaderOpaque = nullptr;
  inline static ShaderProgram* program = nullptr;
  inline static ShaderProgram* programOpaque = nullptr;

  size_t numberOfVertices;
  size_t numberOfIndices;
};

MeshGeometry::MeshGeometry()
  : m_color(255, 0, 0), m_opacity(255), m_dirty(false), d(new Private)
{}

MeshGeometry::MeshGeometry(const MeshGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices), m_indices(other.m_indices),
    m_color(other.m_color), m_opacity(other.m_opacity),
    m_dirty(true), // Force rendering internals to be rebuilt
    d(new Private)
{}

MeshGeometry::~MeshGeometry()
{
  delete d;
}

void MeshGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void MeshGeometry::update()
{
  if (m_vertices.empty() || m_indices.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);
    d->ibo.upload(m_indices, BufferObject::ElementArrayBuffer);
    d->numberOfVertices = m_vertices.size();
    d->numberOfIndices = m_indices.size();
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

    d->fragmentShaderOpaque = new Shader;
    d->fragmentShaderOpaque->setType(Shader::Fragment);
    d->fragmentShaderOpaque->setSource(mesh_opaque_fs);

    if (!d->vertexShader->compile())
      cout << d->vertexShader->error() << endl;
    if (!d->fragmentShader->compile())
      cout << d->fragmentShader->error() << endl;
    if (!d->fragmentShaderOpaque->compile())
      cout << d->fragmentShaderOpaque->error() << endl;

    if (d->program == nullptr)
      d->program = new ShaderProgram;
    d->program->attachShader(*d->vertexShader);
    d->program->attachShader(*d->fragmentShader);
    if (!d->program->link())
      cout << d->program->error() << endl;

    if (d->programOpaque == nullptr)
      d->programOpaque = new ShaderProgram;
    d->programOpaque->attachShader(*d->vertexShader);
    d->programOpaque->attachShader(*d->fragmentShaderOpaque);
    if (!d->programOpaque->link())
      cout << d->programOpaque->error() << endl;
  }
}

void MeshGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_vertices.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  ShaderProgram* program;
  // If the mesh is opaque, use the opaque shader
  if (m_opacity != 255)
    program = d->program;
  else
    program = d->programOpaque;

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
    std::cout << program->error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices - 1),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vbo.release();
  d->ibo.release();

  program->disableAttributeArray("vector");
  program->disableAttributeArray("color");
  program->disableAttributeArray("normal");

  program->release();
}

void MeshGeometry::addBoundingBox(const Vector3f& minPos, 
                                  const Vector3f& maxPos,
                                  const Vector4ub& color)
{
  // 8 corners of the box
  // near face (z = minPos.z)
  Vector3f v0(minPos.x(), minPos.y(), minPos.z()); // bottom-left-near
  Vector3f v1(maxPos.x(), minPos.y(), minPos.z()); // bottom-right-near
  Vector3f v2(maxPos.x(), maxPos.y(), minPos.z()); // top-right-near
  Vector3f v3(minPos.x(), maxPos.y(), minPos.z()); // top-left-near

  // far face (z = maxPos.z)
  Vector3f v4(minPos.x(), minPos.y(), maxPos.z()); // bottom-left-far
  Vector3f v5(maxPos.x(), minPos.y(), maxPos.z()); // bottom-right-far
  Vector3f v6(maxPos.x(), maxPos.y(), maxPos.z()); // top-right-far
  Vector3f v7(minPos.x(), maxPos.y(), maxPos.z()); // top-left-far

  // For a quick bounding box, let's just give a normal for each face.
  // (If you prefer per-vertex normals that are averaged, you can do that,
  // but for a box it's typical to have face normals.)
  // We'll make a small helper lambda to push back a face:
  auto addFace = [&](const Vector3f& a, const Vector3f& b, const Vector3f& c, 
                     const Vector3f& d, const Vector3f& normal)
  {
    // Each face is 2 triangles: (a,b,c) and (a,c,d)
    // We'll collect positions, normals, color in arrays and then
    // call addVertices(...) + addTriangles(...).

    // The caller of this lambda will hold a temporary arrays:
    Core::Array<Vector3f> faceVerts;
    Core::Array<Vector3f> faceNorms;
    Core::Array<Vector4ub> faceColors;
    Core::Array<unsigned int> faceIndices;

    faceVerts.reserve(4);
    faceNorms.reserve(4);
    faceColors.reserve(4);
    faceIndices.reserve(6);

    // push back 4 corners
    faceVerts.push_back(a);
    faceVerts.push_back(b);
    faceVerts.push_back(c);
    faceVerts.push_back(d);

    // same normal for each corner
    for (int i = 0; i < 4; ++i) {
      faceNorms.push_back(normal);
      faceColors.push_back(color);
    }

    // Triangles
    // 0->1->2,  0->2->3
    faceIndices.push_back(0);
    faceIndices.push_back(1);
    faceIndices.push_back(2);
    faceIndices.push_back(0);
    faceIndices.push_back(2);
    faceIndices.push_back(3);

    // Now add them to "this" MeshGeometry
    // 1) Add vertices returns the *base index* we must offset the faceIndices by
    unsigned int base = addVertices(faceVerts, faceNorms, faceColors);
    // 2) We need to offset faceIndices by 'base'
    for (auto & idx : faceIndices) {
      idx += base;
    }
    // 3) Add triangles to the main index buffer
    addTriangles(faceIndices);
  };

  // near face normal = negative z
  addFace(v0, v1, v2, v3, Vector3f(0.f, 0.f, -1.f));
  // far face normal = +z
  addFace(v5, v4, v7, v6, Vector3f(0.f, 0.f, 1.f));

  // left face normal = -x
  addFace(v4, v0, v3, v7, Vector3f(-1.f, 0.f, 0.f));
  // right face normal = +x
  addFace(v1, v5, v6, v2, Vector3f(1.f, 0.f, 0.f));

  // bottom face normal = -y
  addFace(v4, v5, v1, v0, Vector3f(0.f, -1.f, 0.f));
  // top face normal = +y
  addFace(v3, v2, v6, v7, Vector3f(0.f, 1.f, 0.f));
}


unsigned int MeshGeometry::addVertices(const Core::Array<Vector3f>& v,
                                       const Core::Array<Vector3f>& n,
                                       const Core::Array<Vector4ub>& c)
{
  if (v.size() != n.size() || n.size() != c.size())
    return InvalidIndex;

  size_t result = m_vertices.size();

  auto vIter = v.begin();
  auto vEnd = v.end();
  auto nIter = n.begin();
  auto cIter = c.begin();

  while (vIter != vEnd)
    m_vertices.push_back(PackedVertex(*(cIter++), *(nIter++), *(vIter++)));

  m_dirty = true;

  return static_cast<unsigned int>(result);
}

unsigned int MeshGeometry::addVertices(const Core::Array<Vector3f>& v,
                                       const Core::Array<Vector3f>& n,
                                       const Core::Array<Vector3ub>& c)
{
  if (v.size() != n.size() || n.size() != c.size())
    return InvalidIndex;

  size_t result = m_vertices.size();

  auto vIter = v.begin();
  auto vEnd = v.end();
  auto nIter = n.begin();
  auto cIter = c.begin();

  Vector4ub tmpColor(0, 0, 0, m_opacity);
  while (vIter != vEnd) {
    tmpColor.head<3>() = *(cIter++);
    m_vertices.push_back(PackedVertex(tmpColor, *(nIter++), *(vIter++)));
  }

  m_dirty = true;

  return static_cast<unsigned int>(result);
}

unsigned int MeshGeometry::addVertices(const Core::Array<Vector3f>& v,
                                       const Core::Array<Vector3f>& n)
{
  if (v.size() != n.size())
    return InvalidIndex;

  size_t result = m_vertices.size();

  auto vIter = v.begin();
  auto vEnd = v.end();
  auto nIter = n.begin();

  const Vector4ub tmpColor(m_color[0], m_color[1], m_color[2], m_opacity);
  while (vIter != vEnd)
    m_vertices.push_back(PackedVertex(tmpColor, *(nIter++), *(vIter++)));

  m_dirty = true;

  return static_cast<unsigned int>(result);
}

void MeshGeometry::addTriangle(unsigned int index1, unsigned int index2,
                               unsigned int index3)
{
  m_indices.push_back(index1);
  m_indices.push_back(index2);
  m_indices.push_back(index3);
  m_dirty = true;
}

void MeshGeometry::addTriangles(const Core::Array<unsigned int>& indiceArray)
{
  m_indices.reserve(m_indices.size() + indiceArray.size());
  std::copy(indiceArray.begin(), indiceArray.end(),
            std::back_inserter(m_indices));
  m_dirty = true;
}

void MeshGeometry::clear()
{
  m_vertices.clear();
  m_indices.clear();
  m_dirty = true;
}

} // End namespace Avogadro
