/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "glrenderer.h"

#include "avogadrogl.h"

#include "shader.h"
#include "shaderprogram.h"

#include "spheres_vs.h"
#include "spheres_fs.h"

#include <iostream>

namespace Avogadro {
namespace Rendering {

GLRenderer::GLRenderer() : m_valid(false),
  m_arrayBuffer(BufferObject::ARRAY_BUFFER),
  m_indexBuffer(BufferObject::ELEMENT_ARRAY_BUFFER)
{
}

GLRenderer::~GLRenderer()
{
}

void GLRenderer::initialize()
{
  GLenum result = glewInit();
  m_valid = (result == GLEW_OK);
  if (!m_valid) {
    m_error += "GLEW could not be initialized.\n";
    return;
  }

  if (!GLEW_VERSION_2_0) {
    m_error += "GL version 2.0 is not supported by your graphics driver.\n";
    m_valid = false;
    return;
  }

  glClearColor(0, 0, 0, 0);

  resetCamera();
}

void GLRenderer::resize(int width, int height)
{
  glViewport(0, 0, static_cast<GLint>(width), static_cast<GLint>(height));
  m_camera.setViewport(width, height);
  float distance = std::max(2.0f, m_camera.distance(Vector3f::Zero()));
  m_camera.calculatePerspective(40,
                                distance - 2.0f * m_radius,
                                distance + 2.0f * m_radius);
}

void GLRenderer::render()
{
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

  glEnable(GL_DEPTH_TEST);

  // Check if the VBOs are ready, if not get them ready.
  if (!m_arrayBuffer.ready() || m_scene.dirty()) {
    m_arrayBuffer.upload(m_scene.spheres());
    m_indexBuffer.upload(m_scene.sphereIndices());
    m_scene.setClean();
  }

  // Build and link the shader if it has not been used yet.
  if (m_vertex.type() == Shader::Unknown) {
    m_vertex.setType(Shader::Vertex);
    m_vertex.setSource(spheres_vs);
    m_fragment.setType(Shader::Fragment);
    m_fragment.setSource(spheres_fs);
    if (!m_vertex.compile())
      std::cout << m_vertex.error() << std::endl;
    if (!m_fragment.compile())
      std::cout << m_fragment.error() << std::endl;
    m_program.attachShader(m_vertex);
    m_program.attachShader(m_fragment);
    if (!m_program.link())
      std::cout << m_program.error() << std::endl;
  }

  if (!m_program.bind())
    std::cout << m_program.error() << std::endl;

  m_arrayBuffer.bind();
  m_indexBuffer.bind();

  // Set up out attribute arrays.
  if (!m_program.enableAttributeArray("vertex"))
    std::cout << m_program.error() << std::endl;
  if (!m_program.useAttributeArray("vertex", ColorTextureVertex::vertexOffset(),
                                  Vector3f()))
    std::cout << m_program.error() << std::endl;
  if (!m_program.enableAttributeArray("color"))
    std::cout << m_program.error() << std::endl;
  if (!m_program.useAttributeArray("color", ColorTextureVertex::colorOffset(),
                                  Vector3ub()))
    std::cout << m_program.error() << std::endl;
  if (!m_program.enableAttributeArray("texCoordinate"))
    std::cout << m_program.error() << std::endl;
  if (!m_program.useAttributeArray("texCoordinate", ColorTextureVertex::textureCoordOffset(),
                                  Vector2f()))
    std::cout << m_program.error() << std::endl;
  // Set up our uniforms (model-view and projection matrices right now).
  if (!m_program.setUniformValue("modelView", m_camera.modelView().matrix()))
    std::cout << m_program.error() << std::endl;
  if (!m_program.setUniformValue("projection", m_camera.projection().matrix()))
    std::cout << m_program.error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0, m_scene.sphereIndices().size(),
                      m_scene.sphereIndices().size(), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid *>(NULL));


  m_arrayBuffer.release();
  m_indexBuffer.release();

  m_program.disableAttributeArray("vector");
  m_program.disableAttributeArray("color");
  m_program.disableAttributeArray("texCoordinates");

  m_program.release();

  glDisable(GL_DEPTH_TEST);
}

void GLRenderer::resetCamera()
{
  Vector3f center = m_scene.center();
  m_radius = m_scene.radius() + 5.0;
  m_camera.setIdentity();
  m_camera.translate(-center);
  m_camera.preTranslate(-3.0 * m_radius * Vector3f(0, 0, 1));
  float distance = std::max(2.0f, m_camera.distance(Vector3f::Zero()));
  m_camera.calculatePerspective(40,
                                distance - 2.0f * m_radius,
                                distance + 2.0f * m_radius);
}

std::map<float, Primitive::Identifier> GLRenderer::hits(int x, int y) const
{
  std::map<float, Primitive::Identifier> result;

  // Our ray:
  const Vector3f origin(m_camera.unProject(Vector3f(x, y, 0)));
  const Vector3f end(m_camera.unProject(Vector3f(x, y, 1)));
  const Vector3f direction((end - origin).normalized());

  // Our spheres:
  const std::vector<Sphere> &spheres = m_scene.spheres();

  // Check for intersection.
  Vector3f dst;
  for (size_t i = 0; i < spheres.size(); ++i) {
    const Sphere &sphere = spheres[i];
    const Vector3f &center = sphere.position();
    float radius = sphere.radius();

    // Intersection test taken from chemkit....
    dst = center - origin;
    float B = dst.dot(direction);
    float C = dst.dot(dst) - (radius * radius);
    float D = B * B - C;

    // Test for intersection
    if (D < 0)
      continue;

    // Test for clipping
    if (dst.dot(direction) < 0 || (center - end).dot(direction) > 0)
      continue;

    Primitive::Identifier id = sphere.identifier();
    if (id.type != Primitive::Invalid) {
      /// @todo This might be inaccurate for very large spheres -- may need to
      /// project dst onto direction.
      float depth = dst.norm();
      result.insert(std::pair<float, Primitive::Identifier>(depth, id));
    }
  }

  return result;
}

} // End Rendering namespace
} // End Avogadro namespace
