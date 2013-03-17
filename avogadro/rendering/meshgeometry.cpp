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

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

namespace {
#include "mesh_vs.h"
#include "mesh_fs.h"
}

#include "avogadrogl.h"

#include <avogadro/core/matrix.h>

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class MeshGeometry::Private
{
public:
  Private() { }

  BufferObject vbo;
  BufferObject ibo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;

  size_t numberOfVertices;
  size_t numberOfIndices;
};

MeshGeometry::MeshGeometry() : m_dirty(false), d(new Private),
  m_color(255, 0, 0), m_opacity(255)
{
}

MeshGeometry::~MeshGeometry()
{
  delete d;
}

void MeshGeometry::update()
{
  if (m_vertices.empty() || m_indices.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    cout << "building array buffers...\n";

    std::vector<unsigned int> indices;
    std::vector<ColorNormalVertex> verts;
    indices.reserve(m_indices.size());
    verts.reserve(m_vertices.size());

    std::vector<size_t>::const_iterator itIndex = m_indices.begin();
    std::vector<VertexNormalColor>::const_iterator itVertices = m_vertices.begin();

    for (unsigned int i = 0;
         itIndex != m_indices.end(), itVertices != m_vertices.end();
         ++i, ++itIndex, ++itVertices) {

      // Fill the VBO with triangles.
      verts.push_back(ColorNormalVertex(itVertices->color,
                                           itVertices->normal,
                                           itVertices->vertex));
      indices.push_back(i);
    }

    d->vbo.upload(verts);
    d->ibo.upload(indices);
    d->numberOfVertices = verts.size();
    d->numberOfIndices = indices.size();

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

void MeshGeometry::render(const Camera &camera)
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
  if (!d->program.useAttributeArray("vertex",
                                    ColorNormalVertex::vertexOffset(),
                                    Vector3f())) {
    cout << d->program.error() << endl;
  }
/*  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color",
                                    ColorNormalVertex::colorOffset(),
                                    Vector3ub())) {
    cout << d->program.error() << endl;
  } */
  if (!d->program.enableAttributeArray("normal"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("normal",
                                    ColorNormalVertex::normalOffset(),
                                    Vector3f())) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView",
                                  camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection",
                                  camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }
  Matrix3f normalMatrix =
      camera.modelView().linear().inverse().transpose();
  if (!d->program.setUniformValue("normalMatrix", normalMatrix))
    std::cout << d->program.error() << std::endl;

  if (!d->program.setUniformValue("u_color", m_color))
    cout << d->program.error() << endl;
  if (!d->program.setUniformValue("u_opacity",
                                  static_cast<float>(m_opacity) / 255.0f))
    cout << d->program.error() << endl;

  glEnable(GL_BLEND);
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices),
                      GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid *>(NULL));

  glDisable(GL_BLEND);
  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");
  d->program.disableAttributeArray("texCoordinates");

  d->program.release();
}

void MeshGeometry::addTriangles(const Vector3f *verts, const Vector3f *norms,
                            const Vector3ub *c, size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    m_vertices.push_back(VertexNormalColor(*verts++, *norms++,
                                           c ? *c++ : Vector3ub(255, 0, 0)));
    m_indices.push_back(i);
  }
  m_dirty = true;
}

void MeshGeometry::clear()
{
  m_vertices.clear();
  m_indices.clear();
}

} // End namespace Rendering
} // End namespace Avogadro
