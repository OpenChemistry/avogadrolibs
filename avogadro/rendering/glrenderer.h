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

#ifndef AVOGADRO_RENDERING_GLRENDERER_H
#define AVOGADRO_RENDERING_GLRENDERER_H

#include "avogadrorenderingexport.h"

#include "camera.h"
#include "scene.h"
#include "bufferobject.h"
#include "shader.h"
#include "shaderprogram.h"

#include <string> // For member variables.
#include <vector>

namespace Avogadro {
namespace Rendering {

/*!
 * \class GLRenderer glrenderer.h <avogadro/rendering/glrenderer.h>
 * \brief Render the scene using OpenGL calls.
 * \author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT GLRenderer
{
public:
  GLRenderer();
  ~GLRenderer();

  /*! Initialize the OpenGL context for rendering. */
  void initialize();

  /*! Resize the context in response to window management events. */
  void resize(int width, int height);

  /*! Take care of rendering the scene, requires that the context is current. */
  void render();

  /*! Reset the view to fit the entire scene. */
  void resetCamera();

  /*! Check whether the GL context is valid and supports required features.
   * \sa error() to get more information if the context is not valid.
   */
  bool isValid() const { return m_valid; }

  /*! Get the error message if the context is not valid. Empty if valid. */
  std::string error() const { return m_error; }

  /*! Get the camera for this renderer. */
  const Camera& camera() const;
  Camera& camera();

  /// Get the scene for this renderer.
  const Scene& scene() const { return m_scene; }
  Scene& scene() { return m_scene; }

private:
  bool m_valid;
  std::string m_error;
  Camera m_camera;
  Scene m_scene;
  float m_radius;

  BufferObject m_arrayBuffer;
  BufferObject m_indexBuffer;

  ShaderProgram m_program;
  Shader        m_vertex;
  Shader        m_fragment;
};

inline const Camera& GLRenderer::camera() const
{
  return m_camera;
}

inline Camera& GLRenderer::camera()
{
  return m_camera;
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_GLRENDERER_H
