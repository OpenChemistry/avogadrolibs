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

#include "spheregeometry.h"

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

#include "visitor.h"

namespace {
#include "spheres_fs.h"
#include "spheres_vs.h"
} // namespace

#include "avogadrogl.h"

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

using Core::Array;

class SphereGeometry::Private
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

SphereGeometry::SphereGeometry() : m_dirty(false), d(new Private) {}

SphereGeometry::SphereGeometry(const SphereGeometry& other)
  : Drawable(other), m_spheres(other.m_spheres), m_indices(other.m_indices),
    m_dirty(true), d(new Private)
{}

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

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    std::vector<unsigned int> sphereIndices;
    std::vector<ColorTextureVertex> sphereVertices;
    sphereIndices.reserve(m_indices.size() * 4);
    sphereVertices.reserve(m_spheres.size() * 4);

    std::vector<size_t>::const_iterator itIndex = m_indices.begin();
    std::vector<SphereColor>::const_iterator itSphere = m_spheres.begin();

    for (size_t i = 0;
         itIndex != m_indices.end() && itSphere != m_spheres.end();
         ++i, ++itIndex, ++itSphere) {
      // Use our packed data structure...
      float r = itSphere->radius;
      unsigned int index = 4 * static_cast<unsigned int>(i);
      ColorTextureVertex vert(itSphere->center, itSphere->color,
                              Vector2f(-r, -r));
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f(-r, r);
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f(r, -r);
      sphereVertices.push_back(vert);
      vert.textureCoord = Vector2f(r, r);
      sphereVertices.push_back(vert);

      // 6 indexed vertices to draw a quad...
      sphereIndices.push_back(index + 0);
      sphereIndices.push_back(index + 1);
      sphereIndices.push_back(index + 2);
      sphereIndices.push_back(index + 3);
      sphereIndices.push_back(index + 2);
      sphereIndices.push_back(index + 1);

      // m_spheres.push_back(Sphere(position, r, id, color));
    }

    if (!d->vbo.upload(sphereVertices, BufferObject::ArrayBuffer))
      cout << d->vbo.error() << endl;

    if (!d->ibo.upload(sphereIndices, BufferObject::ElementArrayBuffer))
      cout << d->ibo.error() << endl;

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

void SphereGeometry::render(const Camera& camera)
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
  if (!d->program.useAttributeArray(
        "vertex", ColorTextureVertex::vertexOffset(),
        sizeof(ColorTextureVertex), FloatType, 3, ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color", ColorTextureVertex::colorOffset(),
                                    sizeof(ColorTextureVertex), UCharType, 3,
                                    ShaderProgram::Normalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("texCoordinate"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray(
        "texCoordinate", ColorTextureVertex::textureCoordOffset(),
        sizeof(ColorTextureVertex), FloatType, 2, ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView", camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection", camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("opacity", m_opacity)) {
    cout << d->program.error() << endl;
  }

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0, static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(NULL));

  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");
  d->program.disableAttributeArray("texCoordinates");

  d->program.release();
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
      float rootD = static_cast<float>(sqrt(D));
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

    int in = 0;
    for (in = 0; in < 4; ++in) {
      float dist = (sphere.center - f.points[2 * in]).dot(f.planes[in]);
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

} // End namespace Rendering
} // End namespace Avogadro
