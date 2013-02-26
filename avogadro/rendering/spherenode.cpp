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

#include "spherenode.h"

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

namespace {
#include "spheres_vs.h"
#include "spheres_fs.h"
}

#include "avogadrogl.h"

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class SphereNode::Private
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

SphereNode::SphereNode() : m_dirty(false), d(new Private)
{
}

SphereNode::~SphereNode()
{
  delete d;
}

void SphereNode::update()
{
  if (m_indices.empty() || m_spheres.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    cout << "building array buffers...\n";
    std::vector<unsigned int> sphereIndices;
    std::vector<ColorTextureVertex> sphereVertices;
    sphereIndices.reserve(m_indices.size() * 4);
    sphereVertices.reserve(m_spheres.size() * 4);

    std::vector<size_t>::const_iterator itIndex = m_indices.begin();
    std::vector<SphereColor>::const_iterator itSphere = m_spheres.begin();

    for (unsigned int i = 0;
         itIndex != m_indices.end(), itSphere != m_spheres.end();
         ++i, ++itIndex, ++itSphere) {
      // Use our packed data structure...
      float r = itSphere->radius;
      unsigned int index = 4 * (*itIndex);
      ColorTextureVertex vert(itSphere->center, itSphere->color,
                              Vector2f(-r, -r));
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f(-r, r);
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f( r,-r);
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f( r, r);
      sphereVertices.push_back(vert);

      // 6 indexed vertices to draw a quad...
      sphereIndices.push_back(index + 0);
      sphereIndices.push_back(index + 1);
      sphereIndices.push_back(index + 2);
      sphereIndices.push_back(index + 3);
      sphereIndices.push_back(index + 2);
      sphereIndices.push_back(index + 1);

      //m_spheres.push_back(Sphere(position, r, id, color));
    }

    d->vbo.upload(sphereVertices);
    d->ibo.upload(sphereIndices);
    d->numberOfVertices = sphereVertices.size();
    d->numberOfIndices = sphereIndices.size();

    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(spheres_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(spheres_fs);
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

void SphereNode::render(const Camera &camera)
{
  if (m_indices.empty() || m_spheres.empty())
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
                                    ColorTextureVertex::vertexOffset(),
                                    Vector3f())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color",
                                    ColorTextureVertex::colorOffset(),
                                    Vector3ub())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("texCoordinate"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("texCoordinate",
                                    ColorTextureVertex::textureCoordOffset(),
                                    Vector2f())) {
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

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices),
                      GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid *>(NULL));

  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");
  d->program.disableAttributeArray("texCoordinates");

  d->program.release();
}

void SphereNode::addSphere(const Vector3f &position, const Vector3ub &color,
                           float radius)
{
  m_dirty = true;
  m_spheres.push_back(SphereColor(position, radius, color));
  m_indices.push_back(m_indices.size());
}

void SphereNode::clear()
{
  m_spheres.clear();
  m_indices.clear();
}

} // End namespace Rendering
} // End namespace Avogadro
