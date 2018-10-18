/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

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
#include "mesh_vs.h"
}

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

const unsigned int MeshGeometry::InvalidIndex =
  std::numeric_limits<unsigned int>::max();

class MeshGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;

  size_t numberOfVertices;
  size_t numberOfIndices;
};

MeshGeometry::MeshGeometry()
  : m_color(255, 0, 0), m_opacity(255), m_dirty(false), d(new Private)
{
}

MeshGeometry::MeshGeometry(const MeshGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices), m_indices(other.m_indices),
    m_color(other.m_color), m_opacity(other.m_opacity),
    m_dirty(true), // Force rendering internals to be rebuilt
    d(new Private)
{
}

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
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(mesh_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(mesh_fs);
    if (!d->vertexShader.compile())
      cout << d->vertexShader.error() << endl;
    if (!d->fragmentShader.compile())
      cout << d->fragmentShader.error() << endl;
    d->program.attachShader(d->vertexShader);
    d->program.attachShader(d->fragmentShader);
    if (!d->program.link())
      cout << d->program.error() << endl;
  }
}

void MeshGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_vertices.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  if (!d->program.bind())
    cout << d->program.error() << endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!d->program.enableAttributeArray("vertex"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("vertex", PackedVertex::vertexOffset(),
                                    sizeof(PackedVertex), FloatType, 3,
                                    ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color", PackedVertex::colorOffset(),
                                    sizeof(PackedVertex), UCharType, 4,
                                    ShaderProgram::Normalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("normal"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("normal", PackedVertex::normalOffset(),
                                    sizeof(PackedVertex), FloatType, 3,
                                    ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView", camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection", camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }
  Matrix3f normalMatrix = camera.modelView().linear().inverse().transpose();
  if (!d->program.setUniformValue("normalMatrix", normalMatrix))
    std::cout << d->program.error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices - 1),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");
  d->program.disableAttributeArray("normal");

  d->program.release();
}

unsigned int MeshGeometry::addVertices(const Core::Array<Vector3f>& v,
                                       const Core::Array<Vector3f>& n,
                                       const Core::Array<Vector4ub>& c)
{
  if (v.size() != n.size() || n.size() != c.size())
    return InvalidIndex;

  size_t result = m_vertices.size();

  Core::Array<Vector3f>::const_iterator vIter = v.begin();
  Core::Array<Vector3f>::const_iterator vEnd = v.end();
  Core::Array<Vector3f>::const_iterator nIter = n.begin();
  Core::Array<Vector4ub>::const_iterator cIter = c.begin();

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

  Core::Array<Vector3f>::const_iterator vIter = v.begin();
  Core::Array<Vector3f>::const_iterator vEnd = v.end();
  Core::Array<Vector3f>::const_iterator nIter = n.begin();
  Core::Array<Vector3ub>::const_iterator cIter = c.begin();

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

  Core::Array<Vector3f>::const_iterator vIter = v.begin();
  Core::Array<Vector3f>::const_iterator vEnd = v.end();
  Core::Array<Vector3f>::const_iterator nIter = n.begin();

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

} // End namespace Rendering
} // End namespace Avogadro
