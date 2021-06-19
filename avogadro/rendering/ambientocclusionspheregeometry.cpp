/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.
  Copyright 2013 Tim Vandermeersch <tim.vandermeersch@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "ambientocclusionspheregeometry.h"

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

#include "visitor.h"

namespace {
#include "sphere_ao_bake_fs.h"
#include "sphere_ao_bake_vs.h"
#include "sphere_ao_depth_fs.h"
#include "sphere_ao_depth_vs.h"
#include "sphere_ao_render_fs.h"
#include "sphere_ao_render_vs.h"

const int num_ao_points = 162;
const float ao_points[] = {
  0.850650808352f,
  0.525731112119f,
  0.0f,
  -0.850650808352f,
  0.525731112119f,
  0.0f,
  0.850650808352f,
  -0.525731112119f,
  0.0f,
  -0.850650808352f,
  -0.525731112119f,
  0.0f,
  0.525731112119f,
  0.0f,
  0.850650808352f,
  0.525731112119f,
  0.0f,
  -0.850650808352f,
  -0.525731112119f,
  0.0f,
  0.850650808352f,
  -0.525731112119f,
  0.0f,
  -0.850650808352f,
  0.0f,
  0.850650808352f,
  0.525731112119f,
  0.0f,
  -0.850650808352f,
  0.525731112119f,
  0.0f,
  0.850650808352f,
  -0.525731112119f,
  0.0f,
  -0.850650808352f,
  -0.525731112119f,
  0.5f,
  0.809016994375f,
  0.309016994375f,
  0.309016994375f,
  0.5f,
  0.809016994375f,
  0.809016994375f,
  0.309016994375f,
  0.5f,
  0.809016994375f,
  0.309016994375f,
  -0.5f,
  0.309016994375f,
  0.5f,
  -0.809016994375f,
  0.5f,
  0.809016994375f,
  -0.309016994375f,
  0.809016994375f,
  -0.309016994375f,
  0.5f,
  0.309016994375f,
  -0.5f,
  0.809016994375f,
  0.5f,
  -0.809016994375f,
  0.309016994375f,
  0.5f,
  -0.809016994375f,
  -0.309016994375f,
  0.309016994375f,
  -0.5f,
  -0.809016994375f,
  0.809016994375f,
  -0.309016994375f,
  -0.5f,
  -0.809016994375f,
  0.309016994375f,
  0.5f,
  -0.309016994375f,
  0.5f,
  0.809016994375f,
  -0.5f,
  0.809016994375f,
  0.309016994375f,
  -0.5f,
  0.809016994375f,
  -0.309016994375f,
  -0.309016994375f,
  0.5f,
  -0.809016994375f,
  -0.809016994375f,
  0.309016994375f,
  -0.5f,
  -0.5f,
  -0.809016994375f,
  0.309016994375f,
  -0.309016994375f,
  -0.5f,
  0.809016994375f,
  -0.809016994375f,
  -0.309016994375f,
  0.5f,
  -0.809016994375f,
  -0.309016994375f,
  -0.5f,
  -0.309016994375f,
  -0.5f,
  -0.809016994375f,
  -0.5f,
  -0.809016994375f,
  -0.309016994375f,
  0.0f,
  1.0f,
  0.0f,
  0.0f,
  -1.0f,
  0.0f,
  1.0f,
  0.0f,
  0.0f,
  -1.0f,
  0.0f,
  0.0f,
  0.0f,
  0.0f,
  1.0f,
  0.0f,
  0.0f,
  -1.0f,
  0.702046444776f,
  0.69378047756f,
  0.16062203564f,
  0.688190960236f,
  0.587785252292f,
  0.425325404176f,
  0.862668480416f,
  0.433888564553f,
  0.259891913008f,
  0.16062203564f,
  0.702046444776f,
  0.69378047756f,
  0.425325404176f,
  0.688190960236f,
  0.587785252292f,
  0.259891913008f,
  0.862668480416f,
  0.433888564553f,
  0.69378047756f,
  0.16062203564f,
  0.702046444776f,
  0.587785252292f,
  0.425325404176f,
  0.688190960236f,
  0.433888564553f,
  0.259891913008f,
  0.862668480416f,
  0.862668480416f,
  0.433888564553f,
  -0.259891913008f,
  0.688190960236f,
  0.587785252292f,
  -0.425325404176f,
  0.702046444776f,
  0.69378047756f,
  -0.16062203564f,
  0.433888564553f,
  0.259891913008f,
  -0.862668480416f,
  0.587785252292f,
  0.425325404176f,
  -0.688190960236f,
  0.69378047756f,
  0.16062203564f,
  -0.702046444776f,
  0.259891913008f,
  0.862668480416f,
  -0.433888564553f,
  0.425325404176f,
  0.688190960236f,
  -0.587785252292f,
  0.16062203564f,
  0.702046444776f,
  -0.69378047756f,
  0.862668480416f,
  -0.433888564553f,
  0.259891913008f,
  0.688190960236f,
  -0.587785252292f,
  0.425325404176f,
  0.702046444776f,
  -0.69378047756f,
  0.16062203564f,
  0.433888564553f,
  -0.259891913008f,
  0.862668480416f,
  0.587785252292f,
  -0.425325404176f,
  0.688190960236f,
  0.69378047756f,
  -0.16062203564f,
  0.702046444776f,
  0.259891913008f,
  -0.862668480416f,
  0.433888564553f,
  0.425325404176f,
  -0.688190960236f,
  0.587785252292f,
  0.16062203564f,
  -0.702046444776f,
  0.69378047756f,
  0.702046444776f,
  -0.69378047756f,
  -0.16062203564f,
  0.688190960236f,
  -0.587785252292f,
  -0.425325404176f,
  0.862668480416f,
  -0.433888564553f,
  -0.259891913008f,
  0.16062203564f,
  -0.702046444776f,
  -0.69378047756f,
  0.425325404176f,
  -0.688190960236f,
  -0.587785252292f,
  0.259891913008f,
  -0.862668480416f,
  -0.433888564553f,
  0.69378047756f,
  -0.16062203564f,
  -0.702046444776f,
  0.587785252292f,
  -0.425325404176f,
  -0.688190960236f,
  0.433888564553f,
  -0.259891913008f,
  -0.862668480416f,
  -0.862668480416f,
  0.433888564553f,
  0.259891913008f,
  -0.688190960236f,
  0.587785252292f,
  0.425325404176f,
  -0.702046444776f,
  0.69378047756f,
  0.16062203564f,
  -0.433888564553f,
  0.259891913008f,
  0.862668480416f,
  -0.587785252292f,
  0.425325404176f,
  0.688190960236f,
  -0.69378047756f,
  0.16062203564f,
  0.702046444776f,
  -0.259891913008f,
  0.862668480416f,
  0.433888564553f,
  -0.425325404176f,
  0.688190960236f,
  0.587785252292f,
  -0.16062203564f,
  0.702046444776f,
  0.69378047756f,
  -0.702046444776f,
  0.69378047756f,
  -0.16062203564f,
  -0.688190960236f,
  0.587785252292f,
  -0.425325404176f,
  -0.862668480416f,
  0.433888564553f,
  -0.259891913008f,
  -0.16062203564f,
  0.702046444776f,
  -0.69378047756f,
  -0.425325404176f,
  0.688190960236f,
  -0.587785252292f,
  -0.259891913008f,
  0.862668480416f,
  -0.433888564553f,
  -0.69378047756f,
  0.16062203564f,
  -0.702046444776f,
  -0.587785252292f,
  0.425325404176f,
  -0.688190960236f,
  -0.433888564553f,
  0.259891913008f,
  -0.862668480416f,
  -0.702046444776f,
  -0.69378047756f,
  0.16062203564f,
  -0.688190960236f,
  -0.587785252292f,
  0.425325404176f,
  -0.862668480416f,
  -0.433888564553f,
  0.259891913008f,
  -0.16062203564f,
  -0.702046444776f,
  0.69378047756f,
  -0.425325404176f,
  -0.688190960236f,
  0.587785252292f,
  -0.259891913008f,
  -0.862668480416f,
  0.433888564553f,
  -0.69378047756f,
  -0.16062203564f,
  0.702046444776f,
  -0.587785252292f,
  -0.425325404176f,
  0.688190960236f,
  -0.433888564553f,
  -0.259891913008f,
  0.862668480416f,
  -0.862668480416f,
  -0.433888564553f,
  -0.259891913008f,
  -0.688190960236f,
  -0.587785252292f,
  -0.425325404176f,
  -0.702046444776f,
  -0.69378047756f,
  -0.16062203564f,
  -0.433888564553f,
  -0.259891913008f,
  -0.862668480416f,
  -0.587785252292f,
  -0.425325404176f,
  -0.688190960236f,
  -0.69378047756f,
  -0.16062203564f,
  -0.702046444776f,
  -0.259891913008f,
  -0.862668480416f,
  -0.433888564553f,
  -0.425325404176f,
  -0.688190960236f,
  -0.587785252292f,
  -0.16062203564f,
  -0.702046444776f,
  -0.69378047756f,
  0.525731112119f,
  0.850650808352f,
  0.0f,
  0.0f,
  0.961938357784f,
  -0.273266528913f,
  0.26286555606f,
  0.951056516295f,
  -0.162459848116f,
  0.26286555606f,
  0.951056516295f,
  0.162459848116f,
  0.0f,
  0.961938357784f,
  0.273266528913f,
  -0.525731112119f,
  0.850650808352f,
  0.0f,
  -0.26286555606f,
  0.951056516295f,
  0.162459848116f,
  -0.26286555606f,
  0.951056516295f,
  -0.162459848116f,
  0.525731112119f,
  -0.850650808352f,
  0.0f,
  0.0f,
  -0.961938357784f,
  0.273266528913f,
  0.26286555606f,
  -0.951056516295f,
  0.162459848116f,
  0.26286555606f,
  -0.951056516295f,
  -0.162459848116f,
  0.0f,
  -0.961938357784f,
  -0.273266528913f,
  -0.525731112119f,
  -0.850650808352f,
  0.0f,
  -0.26286555606f,
  -0.951056516295f,
  0.162459848116f,
  -0.26286555606f,
  -0.951056516295f,
  -0.162459848116f,
  0.850650808352f,
  0.0f,
  0.525731112119f,
  0.961938357784f,
  -0.273266528913f,
  0.0f,
  0.951056516295f,
  -0.162459848116f,
  0.26286555606f,
  0.951056516295f,
  0.162459848116f,
  0.26286555606f,
  0.961938357784f,
  0.273266528913f,
  0.0f,
  0.850650808352f,
  0.0f,
  -0.525731112119f,
  0.951056516295f,
  0.162459848116f,
  -0.26286555606f,
  0.951056516295f,
  -0.162459848116f,
  -0.26286555606f,
  -0.850650808352f,
  0.0f,
  0.525731112119f,
  -0.961938357784f,
  0.273266528913f,
  0.0f,
  -0.951056516295f,
  0.162459848116f,
  0.26286555606f,
  -0.951056516295f,
  -0.162459848116f,
  0.26286555606f,
  -0.961938357784f,
  -0.273266528913f,
  0.0f,
  -0.850650808352f,
  0.0f,
  -0.525731112119f,
  -0.951056516295f,
  -0.162459848116f,
  -0.26286555606f,
  -0.951056516295f,
  0.162459848116f,
  -0.26286555606f,
  0.0f,
  0.525731112119f,
  0.850650808352f,
  -0.273266528913f,
  0.0f,
  0.961938357784f,
  -0.162459848116f,
  0.26286555606f,
  0.951056516295f,
  0.162459848116f,
  0.26286555606f,
  0.951056516295f,
  0.273266528913f,
  0.0f,
  0.961938357784f,
  0.0f,
  -0.525731112119f,
  0.850650808352f,
  0.162459848116f,
  -0.26286555606f,
  0.951056516295f,
  -0.162459848116f,
  -0.26286555606f,
  0.951056516295f,
  0.0f,
  0.525731112119f,
  -0.850650808352f,
  0.273266528913f,
  0.0f,
  -0.961938357784f,
  0.162459848116f,
  0.26286555606f,
  -0.951056516295f,
  -0.162459848116f,
  0.26286555606f,
  -0.951056516295f,
  -0.273266528913f,
  0.0f,
  -0.961938357784f,
  0.0f,
  -0.525731112119f,
  -0.850650808352f,
  -0.162459848116f,
  -0.26286555606f,
  -0.951056516295f,
  0.162459848116f,
  -0.26286555606f,
  -0.951056516295f,
};
}

#include "avogadrogl.h"

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class AmbientOcclusionRenderer
{
public:
  virtual ~AmbientOcclusionRenderer() {}

  virtual void renderDepth(const Eigen::Matrix4f& modelView,
                           const Eigen::Matrix4f& projection) = 0;
  virtual void renderAO(const Eigen::Matrix4f& modelView,
                        const Eigen::Matrix4f& projection, GLint textureSize,
                        float numDirections) = 0;
};

class AmbientOcclusionBaker
{
public:
  AmbientOcclusionBaker(AmbientOcclusionRenderer* renderer, GLint textureSize_)
    : m_renderer(renderer)
    , m_textureSize(textureSize_)
    , m_depthTexture(0)
    , m_depthFBO(0)
    , m_aoTexture(0)
    , m_aoFBO(0)
  {
    initialize();
  }

  void destroy()
  {
    // delete framebuffers
    glDeleteFramebuffers(1, &m_depthFBO);
    glDeleteFramebuffers(1, &m_aoFBO);
    // delete depth texture
    glDeleteTextures(1, &m_depthTexture);
    // note: ao texture not deleted since it contains the computed data...
  }

  GLint textureSize() const { return m_textureSize; }

  GLuint aoTexture() const { return m_aoTexture; }

  void accumulateAO(const Vector3f& center, float radius)
  {
    // save OpenGL state
    m_openglState.save();

    // set the viewport
    glViewport(0, 0, m_textureSize, m_textureSize);
    // set the clear depth value
    glClearDepth(1.0f);
    // set the clear color
    glClearColor(0.0, 0.0, 0.0, 1.0);
    // enable polygon offset to resolve depth fighting
    glEnable(GL_POLYGON_OFFSET_FILL);
    glPolygonOffset(2.0f, 4.0f);
    // enable alpha blending
    glEnable(GL_BLEND);
    glBlendFunc(GL_ONE, GL_ONE);
    // bind the depth texture for depth lookup
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, m_depthTexture);

    Camera camera;
    camera.calculateOrthographic(-radius, radius, -radius, radius, -radius,
                                 radius);
    Eigen::Matrix4f projection(camera.projection().matrix());

    // clear draw buffer once, AO wil be accumulated using blending
    glBindFramebuffer(GL_FRAMEBUFFER, m_aoFBO);
    glClear(GL_COLOR_BUFFER_BIT);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);

    for (int i = 0; i < num_ao_points; ++i) {
      // random light direction
      Vector3f dir(ao_points[i * 3], ao_points[i * 3 + 1],
                   ao_points[i * 3 + 2]);
      camera.lookAt(center + dir, center, Vector3f(0, 1, 0));
      Eigen::Matrix4f modelView = camera.modelView().matrix();

      // render depth to texture
      renderDepth(modelView, projection);
      // accumulate AO
      renderAO(modelView, projection, num_ao_points);
    }

    // load OpenGL state
    m_openglState.load();
  }

private:
  void initialize()
  {
    // create depth texture & FBO
    createDepthTexture();
    createDepthFBO();
    // create AO texture & FBO
    createAOTexture();
    createAOFBO();
  }

  void checkFramebufferStatus()
  {
    // check framebuffer status
    GLenum status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    switch (status) {
      case GL_FRAMEBUFFER_COMPLETE:
        std::cerr << "GL_FRAMEBUFFER_COMPLETE" << std::endl;
        break;
      case GL_FRAMEBUFFER_UNDEFINED:
        std::cerr << "GL_FRAMEBUFFER_UNDEFINED" << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT" << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT"
                  << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_DRAW_BUFFER:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_DRAW_BUFFER" << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_READ_BUFFER:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_READ_BUFFER" << std::endl;
        break;
      case GL_FRAMEBUFFER_UNSUPPORTED:
        std::cerr << "GL_FRAMEBUFFER_UNSUPPORTED" << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_MULTISAMPLE:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_MULTISAMPLE" << std::endl;
        break;
      case GL_FRAMEBUFFER_INCOMPLETE_LAYER_TARGETS:
        std::cerr << "GL_FRAMEBUFFER_INCOMPLETE_LAYER_TARGETS" << std::endl;
        break;
      default:
        std::cerr << "GL_FRAMEBUFFER_???" << std::endl;
        break;
    }
  }

  void createDepthTexture(GLenum internalFormat = GL_DEPTH_COMPONENT32)
  {
    // create depth texture
    glGenTextures(1, &m_depthTexture);
    // bind the depth texture
    glBindTexture(GL_TEXTURE_2D, m_depthTexture);
    // allocate storage for the texture
    glTexImage2D(GL_TEXTURE_2D,                // target
                 0,                            // level
                 internalFormat,               // internal format
                 m_textureSize, m_textureSize, // texture size
                 0,                            // border
                 GL_DEPTH_COMPONENT,           // format
                 GL_FLOAT,                     // type
                 nullptr);                     // data

    // set the filtering modes
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    // set depth comparison mode
    // this does not work with nvidia driver, works with intel 3000...
    // glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_COMPARE_MODE,
    // GL_COMPARE_REF_TO_TEXTURE);
    // glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_COMPARE_FUNC, GL_LEQUAL);
    // set wrap modes
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    // unbind texture
    glBindTexture(GL_TEXTURE_2D, 0);
  }

  void createDepthFBO()
  {
    // create FBO to render depth into
    glGenFramebuffers(1, &m_depthFBO);
    glBindFramebuffer(GL_FRAMEBUFFER, m_depthFBO);
    // attach the depth texture to the depth FBO
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D,
                           m_depthTexture, 0);

    // disable draw and read buffer
    glDrawBuffer(GL_NONE);
    glReadBuffer(GL_NONE);

    // check framebuffer status
    // checkFramebufferStatus(); // debug...

    // unbind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
  }

  void renderDepth(const Eigen::Matrix4f& modelView,
                   const Eigen::Matrix4f& projection)
  {
    // bind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, m_depthFBO);

    // enable depth test
    glEnable(GL_DEPTH_TEST);
    // clear depth buffer
    glClear(GL_DEPTH_BUFFER_BIT);

    // render the scene
    m_renderer->renderDepth(modelView, projection);

    // unbind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
  }

  void createAOTexture()
  {
    // create AO texture
    glGenTextures(1, &m_aoTexture);
    // bind the AO texture
    glBindTexture(GL_TEXTURE_2D, m_aoTexture);
    // allocate storage for the texture
    glTexImage2D(GL_TEXTURE_2D,                // target
                 0,                            // level
                 GL_RGBA,                      // internal format
                 m_textureSize, m_textureSize, // texture size
                 0,                            // border
                 GL_RGBA,                      // format
                 GL_UNSIGNED_BYTE,             // type
                 nullptr);                     // data

    // set the filtering modes
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    // set wrap modes
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    // unbind texture
    glBindTexture(GL_TEXTURE_2D, 0);
  }

  void createAOFBO()
  {
    // create FBO to render depth into
    glGenFramebuffers(1, &m_aoFBO);
    glBindFramebuffer(GL_FRAMEBUFFER, m_aoFBO);
    // attach the depth texture to the depth FBO
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                           m_aoTexture, 0);

    // disable draw and read buffer
    glReadBuffer(GL_NONE);

    // check framebuffer status
    // checkFramebufferStatus(); // debug...

    // unbind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
  }

  void renderAO(const Eigen::Matrix4f& modelView,
                const Eigen::Matrix4f& projection, int numDirections)
  {
    // bind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, m_aoFBO);

    // disable depth testing
    glDisable(GL_DEPTH_TEST);

    // render the scene
    m_renderer->renderAO(modelView, projection, m_textureSize,
                         static_cast<float>(numDirections));

    // unbind framebuffer
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
  }

  struct OpenGLState
  {
    void save()
    {
      // bound texture
      glGetIntegerv(GL_TEXTURE_BINDING_2D, &boundTexture);
      // viewport
      glGetIntegerv(GL_VIEWPORT, viewport);
      // depth
      glGetBooleanv(GL_DEPTH_TEST, &depthTest);
      glGetFloatv(GL_DEPTH_CLEAR_VALUE, &clearDepthValue);
      // color
      glGetBooleanv(GL_BLEND, &blend);
      glGetIntegerv(GL_BLEND_SRC, &blendSrc);
      glGetIntegerv(GL_BLEND_DST, &blendDst);
      glGetFloatv(GL_COLOR_CLEAR_VALUE, clearColor);
      // polygon offset
      polygonOffset = glIsEnabled(GL_POLYGON_OFFSET_FILL);
      glGetFloatv(GL_POLYGON_OFFSET_FACTOR, &polygonOffsetFactor);
      glGetFloatv(GL_POLYGON_OFFSET_UNITS, &polygonOffsetUnits);
    }

    void load()
    {
      // bound texture
      glBindTexture(GL_TEXTURE_2D, boundTexture);
      // viewport
      glViewport(viewport[0], viewport[1], viewport[2], viewport[3]);
      // depth
      if (!depthTest)
        glDisable(GL_DEPTH_TEST);
      else
        glEnable(GL_DEPTH_TEST);
      glClearDepth(clearDepthValue);
      // color
      glClearColor(clearColor[0], clearColor[1], clearColor[2], clearColor[3]);
      if (!blend)
        glDisable(GL_BLEND);
      else
        glEnable(GL_BLEND);
      glBlendFunc(blendSrc, blendDst);
    }

    // bound texture
    GLint boundTexture;
    // viewport
    GLint viewport[4];
    // depth
    GLboolean depthTest;
    GLfloat clearDepthValue;
    // color
    GLfloat clearColor[4];
    GLboolean blend;
    GLint blendSrc, blendDst;
    // polygon offset
    GLboolean polygonOffset;
    GLfloat polygonOffsetFactor;
    GLfloat polygonOffsetUnits;
  };

  OpenGLState m_openglState;

  AmbientOcclusionRenderer* m_renderer;

  GLint m_textureSize;

  GLuint m_depthTexture;
  GLuint m_depthFBO;
  GLuint m_aoTexture;
  GLuint m_aoFBO;
};

class SphereAmbientOcclusionRenderer : public AmbientOcclusionRenderer
{
public:
  SphereAmbientOcclusionRenderer(BufferObject& vbo, BufferObject& ibo,
                                 int numSpheres, int numVertices,
                                 int numIndices)
    : m_vbo(vbo)
    , m_ibo(ibo)
    , m_numSpheres(numSpheres)
    , m_numVertices(numVertices)
    , m_numIndices(numIndices)
  {
    initialize();
  }

  void renderDepth(const Eigen::Matrix4f& modelView,
                   const Eigen::Matrix4f& projection) override
  {
    // bind buffer objects
    m_vbo.bind();
    m_ibo.bind();

    m_depthProgram.bind();

    // set the uniforms
    if (!m_depthProgram.setUniformValue("u_modelView", modelView)) {
      cout << m_depthProgram.error() << endl;
    }
    if (!m_depthProgram.setUniformValue("u_projection", projection)) {
      cout << m_depthProgram.error() << endl;
    }

    // set the attributes
    if (!m_depthProgram.enableAttributeArray("a_pos"))
      cout << m_depthProgram.error() << endl;
    if (!m_depthProgram.useAttributeArray("a_pos",
                                          ColorTextureVertex::vertexOffset(),
                                          sizeof(ColorTextureVertex), FloatType,
                                          3, ShaderProgram::NoNormalize)) {
      cout << m_depthProgram.error() << endl;
    }
    if (!m_depthProgram.enableAttributeArray("a_corner"))
      cout << m_depthProgram.error() << endl;
    if (!m_depthProgram.useAttributeArray(
          "a_corner", ColorTextureVertex::textureCoordOffset(),
          sizeof(ColorTextureVertex), FloatType, 2,
          ShaderProgram::NoNormalize)) {
      cout << m_depthProgram.error() << endl;
    }

    // draw
    glDrawRangeElements(GL_TRIANGLES, 0, static_cast<GLuint>(m_numVertices),
                        static_cast<GLsizei>(m_numIndices), GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid*>(NULL));

    m_vbo.release();
    m_ibo.release();

    m_depthProgram.disableAttributeArray("a_pos");
    m_depthProgram.disableAttributeArray("a_corner");

    m_depthProgram.release();
  }

  void renderAO(const Eigen::Matrix4f& modelView,
                const Eigen::Matrix4f& projection, GLint textureSize,
                float numDirections) override
  {
    // bind buffer objects
    m_vbo.bind();
    m_ibo.bind();

    m_aoProgram.bind();

    // set the uniforms
    if (!m_aoProgram.setUniformValue("u_modelView", modelView)) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.setUniformValue("u_projection", projection)) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.setUniformValue("u_textureSize",
                                     static_cast<GLfloat>(textureSize))) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.setUniformValue(
          "u_tileSize",
          1.0f / std::ceil(std::sqrt(static_cast<float>(m_numSpheres))))) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.setUniformValue("u_depthTex", 0)) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.setUniformValue("u_intensity",
                                     1.0f / (0.3f * numDirections))) {
      cout << m_aoProgram.error() << endl;
    }

    // set the attributes
    if (!m_aoProgram.enableAttributeArray("a_pos"))
      cout << m_aoProgram.error() << endl;
    if (!m_aoProgram.useAttributeArray("a_pos",
                                       ColorTextureVertex::vertexOffset(),
                                       sizeof(ColorTextureVertex), FloatType, 3,
                                       ShaderProgram::NoNormalize)) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.enableAttributeArray("a_corner"))
      cout << m_aoProgram.error() << endl;
    if (!m_aoProgram.useAttributeArray("a_corner",
                                       ColorTextureVertex::textureCoordOffset(),
                                       sizeof(ColorTextureVertex), FloatType, 2,
                                       ShaderProgram::NoNormalize)) {
      cout << m_aoProgram.error() << endl;
    }
    if (!m_aoProgram.enableAttributeArray("a_tileOffset"))
      cout << m_aoProgram.error() << endl;
    if (!m_aoProgram.useAttributeArray(
          "a_tileOffset", ColorTextureVertex::textureCoord2Offset(),
          sizeof(ColorTextureVertex), FloatType, 2,
          ShaderProgram::NoNormalize)) {
      cout << m_aoProgram.error() << endl;
    }

    // draw
    glDrawRangeElements(GL_TRIANGLES, 0, static_cast<GLuint>(m_numVertices),
                        static_cast<GLsizei>(m_numIndices), GL_UNSIGNED_INT,
                        reinterpret_cast<const GLvoid*>(NULL));

    m_vbo.release();
    m_ibo.release();

    m_aoProgram.disableAttributeArray("a_pos");
    m_aoProgram.disableAttributeArray("a_corner");
    m_aoProgram.disableAttributeArray("a_tileOffset");

    m_aoProgram.release();
  }

  void destroy()
  {
    // depth shader
    m_depthProgram.detachShader(m_depthVertexShader);
    m_depthProgram.detachShader(m_depthFragmentShader);
    m_depthFragmentShader.cleanup();
    m_depthVertexShader.cleanup();
    // ao shader
    m_aoProgram.detachShader(m_aoVertexShader);
    m_aoProgram.detachShader(m_aoFragmentShader);
    m_aoVertexShader.cleanup();
    m_aoFragmentShader.cleanup();
  }

private:
  void initialize()
  {
    // compile depth shaders
    m_depthVertexShader.setType(Shader::Vertex);
    m_depthVertexShader.setSource(sphere_ao_depth_vs);
    if (!m_depthVertexShader.compile())
      cout << m_depthVertexShader.error() << endl;
    m_depthFragmentShader.setType(Shader::Fragment);
    m_depthFragmentShader.setSource(sphere_ao_depth_fs);
    if (!m_depthFragmentShader.compile())
      cout << m_depthFragmentShader.error() << endl;
    // link depth program
    m_depthProgram.attachShader(m_depthVertexShader);
    m_depthProgram.attachShader(m_depthFragmentShader);
    if (!m_depthProgram.link())
      cout << m_depthProgram.error() << endl;

    // compile AO shaders
    m_aoVertexShader.setType(Shader::Vertex);
    m_aoVertexShader.setSource(sphere_ao_bake_vs);
    if (!m_aoVertexShader.compile())
      cout << m_aoVertexShader.error() << endl;
    m_aoFragmentShader.setType(Shader::Fragment);
    m_aoFragmentShader.setSource(sphere_ao_bake_fs);
    if (!m_aoFragmentShader.compile())
      cout << m_aoFragmentShader.error() << endl;
    // link AO program
    m_aoProgram.attachShader(m_aoVertexShader);
    m_aoProgram.attachShader(m_aoFragmentShader);
    if (!m_aoProgram.link())
      cout << m_aoProgram.error() << endl;
  }

  Shader m_depthVertexShader;
  Shader m_depthFragmentShader;
  ShaderProgram m_depthProgram;

  Shader m_aoVertexShader;
  Shader m_aoFragmentShader;
  ShaderProgram m_aoProgram;

  BufferObject& m_vbo;
  BufferObject& m_ibo;
  int m_numSpheres;
  int m_numVertices;
  int m_numIndices;
};

class AmbientOcclusionSphereGeometry::Private
{
public:
  Private()
    : aoTextureSize(1024)
  {}

  BufferObject vbo;
  BufferObject ibo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;

  size_t numberOfVertices;
  size_t numberOfIndices;

  Eigen::Matrix4f translate;
  int aoTextureSize;
  int aoTexture;
};

AmbientOcclusionSphereGeometry::AmbientOcclusionSphereGeometry()
  : m_dirty(false)
  , d(new Private)
{}

AmbientOcclusionSphereGeometry::AmbientOcclusionSphereGeometry(
  const AmbientOcclusionSphereGeometry& other)
  : Drawable(other)
  , m_spheres(other.m_spheres)
  , m_indices(other.m_indices)
  , m_dirty(true)
  , d(new Private)
{}

AmbientOcclusionSphereGeometry::~AmbientOcclusionSphereGeometry()
{
  delete d;
}

void AmbientOcclusionSphereGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void AmbientOcclusionSphereGeometry::update()
{
  if (m_indices.empty() || m_spheres.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    std::vector<unsigned int> sphereIndices;
    std::vector<ColorTextureVertex> sphereVertices;
    sphereIndices.reserve(m_indices.size() * 4);
    sphereVertices.reserve(m_spheres.size() * 4);

    int nSpheres = static_cast<int>(m_spheres.size());
    int nSpheresSquared =
      static_cast<int>(std::ceil(std::sqrt(static_cast<float>(nSpheres))));
    float tileSize = 1.0f / static_cast<float>(nSpheresSquared);
    float halfTileSize = tileSize / 2.0f;
    int tileX = 0;
    int tileY = 0;

    std::vector<size_t>::const_iterator itIndex = m_indices.begin();
    std::vector<SphereColor>::const_iterator itSphere = m_spheres.begin();

    // calculate center
    Vector3f center(Vector3f::Zero());
    for (std::vector<SphereColor>::const_iterator i = m_spheres.begin();
         i != m_spheres.end(); ++i)
      center += i->center;
    center /= static_cast<float>(nSpheres);

    /*
    d->translate = Eigen::Matrix4f::Identity();
    d->translate(0, 3) = center.x();
    d->translate(1, 3) = center.y();
    d->translate(2, 3) = center.z();
    */

    // calculate radius
    float radius = 0.0f;
    for (std::vector<SphereColor>::const_iterator i = m_spheres.begin();
         i != m_spheres.end(); ++i)
      if ((i->center - center).norm() > radius)
        radius = (i->center - center).norm();

    for (unsigned int i = 0;
         itIndex != m_indices.end() && itSphere != m_spheres.end();
         ++i, ++itIndex, ++itSphere) {
      // Use our packed data structure...
      float r = itSphere->radius;
      unsigned int index = 4 * static_cast<unsigned int>(*itIndex);
      ColorTextureVertex vert(
        itSphere->center, itSphere->color, Vector2f(-r, -r),
        Vector2f(halfTileSize + tileSize * static_cast<float>(tileX),
                 halfTileSize + tileSize * static_cast<float>(tileY)));
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

      ++tileX;
      if (tileX >= nSpheresSquared) {
        // start new tile row
        tileX = 0;
        ++tileY;
      }
    }

    d->vbo.upload(sphereVertices, BufferObject::ArrayBuffer);
    d->ibo.upload(sphereIndices, BufferObject::ElementArrayBuffer);
    d->numberOfVertices = sphereVertices.size();
    d->numberOfIndices = sphereIndices.size();

    SphereAmbientOcclusionRenderer aoSphereRenderer(
      d->vbo, d->ibo, static_cast<int>(m_spheres.size()),
      static_cast<int>(d->numberOfVertices),
      static_cast<int>(d->numberOfIndices));
    AmbientOcclusionBaker baker(&aoSphereRenderer, d->aoTextureSize);
    baker.accumulateAO(center, radius + 2.0f);
    d->aoTexture = baker.aoTexture();
    baker.destroy();
    aoSphereRenderer.destroy();

    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(sphere_ao_render_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(sphere_ao_render_fs);
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

void AmbientOcclusionSphereGeometry::render(const Camera& camera)
{
  if (m_indices.empty() || m_spheres.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, d->aoTexture);

  if (!d->program.bind())
    cout << d->program.error() << endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!d->program.enableAttributeArray("a_pos"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("a_pos", ColorTextureVertex::vertexOffset(),
                                    sizeof(ColorTextureVertex), FloatType, 3,
                                    ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("a_corner"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray(
        "a_corner", ColorTextureVertex::textureCoordOffset(),
        sizeof(ColorTextureVertex), FloatType, 2, ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("a_tileOffset"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray(
        "a_tileOffset", ColorTextureVertex::textureCoord2Offset(),
        sizeof(ColorTextureVertex), FloatType, 2, ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("a_color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray(
        "a_color", ColorTextureVertex::colorOffset(),
        sizeof(ColorTextureVertex), UCharType, 3, ShaderProgram::Normalize)) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms
  if (!d->program.setUniformValue("u_modelView", camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue(
        "u_invModelView",
        Eigen::Matrix3f(
          camera.modelView().matrix().block<3, 3>(0, 0).inverse()))) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("u_projection",
                                  camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("u_tex", 0)) {
    cout << d->program.error() << endl;
  }

  // To avoid texture interpolation from neighboring tiles, texture coords are
  // scaled such that half a texel is removed from all sides of a tile.

  // width of a singl texel in texture coordinates [0, 1]
  float texel = 1.0f / static_cast<float>(d->aoTextureSize);
  // with of a single tile in texture coordinates [0, 1]
  float tile = 1.f / std::ceil(std::sqrt(static_cast<float>(m_spheres.size())));

  // The uv coordinates, centered around the tileOffset are originally in the
  // range [-1, 1]. The denominator below ensures that these are scaled to
  // values matching exactly one tile. The numerator is one minus a factor
  // to ensure half a tile on each side is never reached to avoid texture
  // interpolation taking values from neighboring texels into account.
  if (!d->program.setUniformValue(
        "u_texScale", (1.0f - 2.0f * texel / tile) /
                        (2.0f * std::ceil(std::sqrt(
                                  static_cast<float>(m_spheres.size())))))) {
    cout << d->program.error() << endl;
  }

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0, static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(NULL));

  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("a_pos");
  d->program.disableAttributeArray("a_color");
  d->program.disableAttributeArray("a_corner");
  d->program.disableAttributeArray("a_tileOffset");

  d->program.release();
}

std::multimap<float, Identifier> AmbientOcclusionSphereGeometry::hits(
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
    if (D < 0)
      continue;

    // Test for clipping
    if (B < 0 || (sphere.center - rayEnd).dot(rayDirection) > 0)
      continue;

    Identifier id;
    id.molecule = m_identifier.molecule;
    id.type = m_identifier.type;
    id.index = i;
    if (id.type != InvalidType) {
      float rootD = static_cast<float>(sqrt(D));
      float depth = std::min(std::abs(B + rootD), std::abs(B - rootD));
      result.insert(std::pair<float, Identifier>(depth, id));
    }
  }
  return result;
}

void AmbientOcclusionSphereGeometry::addSphere(const Vector3f& position,
                                               const Vector3ub& color,
                                               float radius)
{
  m_dirty = true;
  m_spheres.push_back(SphereColor(position, radius, color));
  m_indices.push_back(m_indices.size());
}

void AmbientOcclusionSphereGeometry::clear()
{
  m_spheres.clear();
  m_indices.clear();
}

} // End namespace Rendering
} // End namespace Avogadro
