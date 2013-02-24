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
#include "spherenode.h"

#include <avogadro/core/matrix.h>

#include "spheres_vs.h"
#include "spheres_fs.h"

#include "cylinders_vs.h"
#include "cylinders_fs.h"

#include <iostream>

namespace Avogadro {
namespace Rendering {

GLRenderer::GLRenderer() : m_valid(false),
  m_sphereArrayBuffer(BufferObject::ARRAY_BUFFER),
  m_sphereIndexBuffer(BufferObject::ELEMENT_ARRAY_BUFFER),
  m_cylinderArrayBuffer(BufferObject::ARRAY_BUFFER),
  m_cylinderIndexBuffer(BufferObject::ELEMENT_ARRAY_BUFFER)
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

  if (m_scene.rootNode().children().size()) {
    std::cout << "root node has " << m_scene.rootNode().children().size() << " children\n";
    GroupNode *node = m_scene.rootNode().children().front()->cast<GroupNode>();
    if (node && node->children().size()) {
      GroupNode *engine = node->children().front()->cast<GroupNode>();
      if (engine == NULL || engine->children().size() == 0)
        return;
      SphereNode *spheres = dynamic_cast<SphereNode *>(engine->children().front());
      if (spheres) {
        std::cout << "Blimey - we have a sphere node with " << spheres->size()
                  << " spheres in it!\n";
        spheres->render(m_camera);
      }
      else {
        std::cout << "Bugger - not a sphere node...\n";
      }
    }
  }

  // Check if the VBOs are ready, if not get them ready.
  if (!m_sphereArrayBuffer.ready() || m_scene.dirty()) {
    m_sphereArrayBuffer.upload(m_scene.sphereVertices());
    m_sphereIndexBuffer.upload(m_scene.sphereIndices());
    m_cylinderArrayBuffer.upload(m_scene.cylinderVertices());
    m_cylinderIndexBuffer.upload(m_scene.cylinderIndices());

    m_triArrayBuffer.upload(m_scene.triangleVertices());
    m_triIndexBuffer.upload(m_scene.triangleIndices());

    m_scene.setClean();
  }

  if (m_scene.sphereCount() != 0) {

    // Build and link the shader if it has not been used yet.
    if (m_sphereVertexShader.type() == Shader::Unknown) {
      m_sphereVertexShader.setType(Shader::Vertex);
      m_sphereVertexShader.setSource(spheres_vs);
      m_sphereFragmentShader.setType(Shader::Fragment);
      m_sphereFragmentShader.setSource(spheres_fs);
      if (!m_sphereVertexShader.compile())
        std::cout << m_sphereVertexShader.error() << std::endl;
      if (!m_sphereFragmentShader.compile())
        std::cout << m_sphereFragmentShader.error() << std::endl;
      m_sphereProgram.attachShader(m_sphereVertexShader);
      m_sphereProgram.attachShader(m_sphereFragmentShader);
      if (!m_sphereProgram.link())
        std::cout << m_sphereProgram.error() << std::endl;
    }

    if (!m_sphereProgram.bind())
      std::cout << m_sphereProgram.error() << std::endl;

    m_sphereArrayBuffer.bind();
    m_sphereIndexBuffer.bind();

    // Set up our attribute arrays.
    if (!m_sphereProgram.enableAttributeArray("vertex"))
      std::cout << m_sphereProgram.error() << std::endl;
    if (!m_sphereProgram.useAttributeArray("vertex",
                                           ColorTextureVertex::vertexOffset(),
                                           Vector3f())) {
      std::cout << m_sphereProgram.error() << std::endl;
    }
    if (!m_sphereProgram.enableAttributeArray("color"))
      std::cout << m_sphereProgram.error() << std::endl;
    if (!m_sphereProgram.useAttributeArray("color",
                                           ColorTextureVertex::colorOffset(),
                                           Vector3ub())) {
      std::cout << m_sphereProgram.error() << std::endl;
    }
    if (!m_sphereProgram.enableAttributeArray("texCoordinate"))
      std::cout << m_sphereProgram.error() << std::endl;
    if (!m_sphereProgram.useAttributeArray("texCoordinate",
                                           ColorTextureVertex::textureCoordOffset(),
                                           Vector2f())) {
      std::cout << m_sphereProgram.error() << std::endl;
    }

    // Set up our uniforms (model-view and projection matrices right now).
    if (!m_sphereProgram.setUniformValue("modelView",
                                         m_camera.modelView().matrix())) {
      std::cout << m_sphereProgram.error() << std::endl;
    }
    if (!m_sphereProgram.setUniformValue("projection",
                                         m_camera.projection().matrix())) {
      std::cout << m_sphereProgram.error() << std::endl;
    }

    // Render the loaded spheres using the shader and bound VBO.
    glDrawRangeElements(GL_TRIANGLES, 0,
                        static_cast<GLuint>(m_scene.sphereVertices().size()),
                        static_cast<GLsizei>(m_scene.sphereIndices().size()),
                        GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid *>(NULL));


    m_sphereArrayBuffer.release();
    m_sphereIndexBuffer.release();

    m_sphereProgram.disableAttributeArray("vector");
    m_sphereProgram.disableAttributeArray("color");
    m_sphereProgram.disableAttributeArray("texCoordinates");

    m_sphereProgram.release();
  }

  // Cylinders:
  if (m_scene.cylinderCount() > 0 || m_scene.triangleVertices().size()) {

    // Build and link the shader if it has not been used yet.
    if (m_cylinderVertexShader.type() == Shader::Unknown) {
      m_cylinderVertexShader.setType(Shader::Vertex);
      m_cylinderVertexShader.setSource(cylinders_vs);
      m_cylinderFragmentShader.setType(Shader::Fragment);
      m_cylinderFragmentShader.setSource(cylinders_fs);
      if (!m_cylinderVertexShader.compile())
        std::cout << m_cylinderVertexShader.error() << std::endl;
      if (!m_cylinderFragmentShader.compile())
        std::cout << m_cylinderFragmentShader.error() << std::endl;
      m_cylinderProgram.attachShader(m_cylinderVertexShader);
      m_cylinderProgram.attachShader(m_cylinderFragmentShader);
      if (!m_cylinderProgram.link())
        std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.bind())
      std::cout << m_cylinderProgram.error() << std::endl;

    m_cylinderArrayBuffer.bind();
    m_cylinderIndexBuffer.bind();

    // Set up out attribute arrays.
    if (!m_cylinderProgram.enableAttributeArray("vertex"))
      std::cout << m_cylinderProgram.error() << std::endl;
    if (!m_cylinderProgram.useAttributeArray("vertex",
                                             ColorNormalVertex::vertexOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("normal"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("normal",
                                             ColorNormalVertex::normalOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("color"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("color",
                                             ColorNormalVertex::colorOffset(),
                                             Vector3ub())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    // Set up our uniforms
    if (!m_cylinderProgram.setUniformValue("modelView",
                                           m_camera.modelView().matrix())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }
    if (!m_cylinderProgram.setUniformValue("projection",
                                           m_camera.projection().matrix())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }
    Matrix3f normalMatrix =
        m_camera.modelView().linear().inverse().transpose();
    if (!m_cylinderProgram.setUniformValue("normalMatrix", normalMatrix))
      std::cout << m_cylinderProgram.error() << std::endl;

    glDrawRangeElements(GL_TRIANGLES, 0,
                        static_cast<GLuint>(m_scene.cylinderVertices().size()),
                        static_cast<GLsizei>(m_scene.cylinderIndices().size()),
                        GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid *>(NULL));

    m_cylinderArrayBuffer.release();
    m_cylinderIndexBuffer.release();

    m_cylinderProgram.disableAttributeArray("normal");
    m_cylinderProgram.disableAttributeArray("vertex");
    m_cylinderProgram.disableAttributeArray("color");

    m_triArrayBuffer.bind();
    m_triIndexBuffer.bind();
    // Set up out attribute arrays.
    if (!m_cylinderProgram.enableAttributeArray("vertex"))
      std::cout << m_cylinderProgram.error() << std::endl;
    if (!m_cylinderProgram.useAttributeArray("vertex",
                                             ColorNormalVertex::vertexOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("normal"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("normal",
                                             ColorNormalVertex::normalOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("color"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("color",
                                             ColorNormalVertex::colorOffset(),
                                             Vector3ub())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    glDrawRangeElements(GL_TRIANGLES, 0,
                        static_cast<GLuint>(m_scene.triangleVertices().size()),
                        static_cast<GLsizei>(m_scene.triangleIndices().size()),
                        GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid *>(NULL));

    m_triArrayBuffer.release();
    m_triIndexBuffer.release();

    m_cylinderProgram.release();
  }

  // Triangle meshes:
  if (m_scene.triangleVertices().size() > 0) {
/*

    // Set up out attribute arrays.
    if (!m_cylinderProgram.enableAttributeArray("vertex"))
      std::cout << m_cylinderProgram.error() << std::endl;
    if (!m_cylinderProgram.useAttributeArray("vertex",
                                             ColorNormalVertex::vertexOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("normal"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("normal",
                                             ColorNormalVertex::normalOffset(),
                                             Vector3f())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    if (!m_cylinderProgram.enableAttributeArray("color"))
      std::cout << m_cylinderProgram.error() << std::endl;

    if (!m_cylinderProgram.useAttributeArray("color",
                                             ColorNormalVertex::colorOffset(),
                                             Vector3ub())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }

    // Set up our uniforms
    if (!m_cylinderProgram.setUniformValue("modelView",
                                           m_camera.modelView().matrix())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }
    if (!m_cylinderProgram.setUniformValue("projection",
                                           m_camera.projection().matrix())) {
      std::cout << m_cylinderProgram.error() << std::endl;
    }
    Matrix3f normalMatrix =
        m_camera.modelView().linear().inverse().transpose();
    if (!m_cylinderProgram.setUniformValue("normalMatrix", normalMatrix))
      std::cout << m_cylinderProgram.error() << std::endl;

    glDrawRangeElements(GL_TRIANGLES, 0,
                        static_cast<GLuint>(m_scene.cylinderVertices().size()),
                        static_cast<GLsizei>(m_scene.cylinderIndices().size()),
                        GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid *>(NULL));

    m_cylinderArrayBuffer.release();
    m_cylinderIndexBuffer.release();

    m_cylinderProgram.disableAttributeArray("normal");
    m_cylinderProgram.disableAttributeArray("vertex");
    m_cylinderProgram.disableAttributeArray("color");

    m_cylinderProgram.release(); */
  }

  glDisable(GL_DEPTH_TEST);
}

void GLRenderer::resetCamera()
{
  Vector3f center = m_scene.center();
  m_radius = m_scene.radius() + 5.0f;
  m_camera.setIdentity();
  m_camera.translate(-center);
  m_camera.preTranslate(-3.0f * m_radius * Vector3f(0.0f, 0.0f, 1.0f));
  float distance = std::max(2.0f, m_camera.distance(Vector3f::Zero()));
  m_camera.calculatePerspective(40.0f,
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
  for (size_t i = 0; i < spheres.size(); ++i) {
    const Sphere &sphere = spheres[i];
    const Vector3f &center = sphere.position();
    float radius = sphere.radius();

    // Intersection test taken from chemkit....
    Vector3f dst = center - origin;
    float B = dst.dot(direction);
    float C = dst.dot(dst) - (radius * radius);
    float D = B * B - C;

    // Test for intersection
    if (D < 0)
      continue;

    // Test for clipping
    if (B < 0 || (center - end).dot(direction) > 0)
      continue;

    Primitive::Identifier id = sphere.identifier();
    if (id.type != Primitive::Invalid) {
      float rootD = static_cast<float>(sqrt(D));
      float depth = std::min(fabs(B + rootD), fabs(B - rootD));
      result.insert(std::pair<float, Primitive::Identifier>(depth, id));
    }
  }

  // Our spheres:
  const std::vector<Cylinder> &cylinders = m_scene.cylinders();
  for (size_t i = 0; i < cylinders.size(); ++i) {
    const Cylinder &cylinder = cylinders[i];

    // Intersection code adapted from chemkit
    Vector3f ao = origin - cylinder.position();
    Vector3f ab = cylinder.direction() * cylinder.length();
    Vector3f aoxab = ao.cross(ab);
    Vector3f vxab = direction.cross(ab);

    float A = vxab.dot(vxab);
    float B = 2 * vxab.dot(aoxab);
    float C = aoxab.dot(aoxab) - ab.dot(ab) *
        (cylinder.radius() * cylinder.radius());
    float D = B*B - 4*A*C;

    // no intersection
    if (D < 0)
      continue;

    float t = std::min((-B + sqrt(D)) / (2.f * A), (-B - sqrt(D)) / (2.f * A));

    Vector3f ip = origin + (direction * t);
    Vector3f ip1 = ip - cylinder.position();
    Vector3f ip2 = ip - (cylinder.position() + ab);

    // intersection below base or above top of the cylinder
    if (ip1.dot(ab) < 0 || ip2.dot(ab) > 0)
      continue;

    // Test for clipping
    Vector3f dst = ip - origin;
    if (dst.dot(direction) < 0 || (ip - end).dot(direction) > 0)
      continue;

    Primitive::Identifier id = cylinder.identifier();
    if (id.type != Primitive::Invalid) {
      float depth = dst.norm();
      result.insert(std::pair<float, Primitive::Identifier>(depth, id));
    }
  }

  return result;
}

} // End Rendering namespace
} // End Avogadro namespace
