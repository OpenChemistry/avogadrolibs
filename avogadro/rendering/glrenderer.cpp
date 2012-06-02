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
    m_scene.radius();
  }

  if (m_vertex.type() == Shader::Unknown) {
    m_vertex.setType(Shader::Vertex);
    m_vertex.setSource(
          "attribute vec4 vertex;\n"
          "attribute vec3 color;\n"
          "attribute vec2 texCoordinate;\n"
          "uniform mat4 modelView;\n"
          "uniform mat4 projection;\n"
          "varying vec2 v_texCoord;\n"
          "varying vec3 fColor;\n"
          "varying vec4 eyePosition;\n"
          "varying float radius;\n"
          "void main()\n"
          "{\n"
          "  radius = abs(texCoordinate.x);\n"
          "  fColor = color;\n"
          "  v_texCoord = texCoordinate / radius;\n"
          "  gl_Position = modelView * vertex;\n"
          "  eyePosition = gl_Position;\n"
          "  gl_Position.xy += texCoordinate;\n"
          "  gl_Position = projection * gl_Position;\n"
          "}\n");
    m_fragment.setType(Shader::Fragment);
    m_fragment.setSource(
          "varying vec2 v_texCoord;\n"
          "varying vec4 eyePosition;\n"
          "varying vec3 fColor;\n"
          "uniform mat3 normal;\n"
          "uniform mat4 projection;\n"
          "varying float radius;\n"
          "void main()\n"
          "{\n"
          "  // Figure out if we are inside our sphere.\n"
          "  float zz = 1.0 - v_texCoord.x*v_texCoord.x - v_texCoord.y*v_texCoord.y;\n"
          "  if (zz <= 0.0)\n"
          "    discard;"
          "  vec3 fragNormal = vec3(v_texCoord, sqrt(zz));\n"
          "\n"
          "  vec3 N = fragNormal;\n"
          "  vec3 L = normalize(vec3(0, 1, 1));\n"
          "  vec3 E = vec3(0, 0, 1);\n"
          "  vec3 H = normalize(L + E);\n"
          "  float df = max(0.0, dot(N, L));\n"
          "  float sf = max(0.0, dot(N, H));\n"
          "  sf = pow(sf, 20.0);\n"
          "  vec3 ambient = fColor / 3.0;\n"
          "  vec3 diffuse = fColor;\n"
          "  vec3 specular = fColor * 3.0;\n"
          "  vec3 color = ambient + df * diffuse + sf * specular;\n"
          "  vec4 pos = eyePosition;\n"
          "  pos.z += fragNormal.z * radius;//The radius is 1.0\n"
          "  pos = projection * pos;\n"
          "  gl_FragDepth = (pos.z / pos.w + 1.0) / 2.0;\n"
          "\n"
          //"  gl_FragColor = vec4(normalize(position), 1.0);\n"
          "  gl_FragColor = vec4(color, 1.0);\n"
          "}\n");
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

} // End Rendering namespace
} // End Avogadro namespace
