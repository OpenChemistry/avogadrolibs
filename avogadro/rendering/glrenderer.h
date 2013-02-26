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
#include "primitive.h"
#include "shader.h"
#include "shaderprogram.h"

#include <map>
#include <string> // For member variables.
#include <vector>

namespace Avogadro {
namespace Rendering {

class GeometryNode;

/**
 * @class GLRenderer glrenderer.h <avogadro/rendering/glrenderer.h>
 * @brief Render the scene using OpenGL calls.
 * @author Marcus D. Hanwell
 */

class AVOGADRORENDERING_EXPORT GLRenderer
{
public:
  GLRenderer();
  ~GLRenderer();

  /** Initialize the OpenGL context for rendering. */
  void initialize();

  /** Resize the context in response to window management events. */
  void resize(int width, int height);

  /** Take care of rendering the scene, requires that the context is current. */
  void render();

  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /** Return the primitives under the display coordinate (x,y), mapped by depth.
   */
  std::map<float, Primitive::Identifier> hits(int x, int y) const;

  /** Return the top primitive under the display coordinate (x,y).
   */
  Primitive::Identifier hit(int x, int y) const;

  /** Check whether the GL context is valid and supports required features.
   * \sa error() to get more information if the context is not valid.
   */
  bool isValid() const { return m_valid; }

  /** Get the error message if the context is not valid. Empty if valid. */
  std::string error() const { return m_error; }

  /** Get the camera for this renderer. */
  const Camera& camera() const;
  Camera& camera();

  /** Get the scene for this renderer. */
  const Scene& scene() const { return m_scene; }
  Scene& scene() { return m_scene; }

private:
  /**
   * @brief Render a group node.
   */
  void render(GroupNode *group);
  void render(GeometryNode *geometry);

  bool m_valid;
  std::string m_error;
  Camera m_camera;
  Scene m_scene;
  float m_radius;

  BufferObject m_sphereArrayBuffer;
  BufferObject m_sphereIndexBuffer;

  ShaderProgram m_sphereProgram;
  Shader        m_sphereVertexShader;
  Shader        m_sphereFragmentShader;

  BufferObject m_cylinderArrayBuffer;
  BufferObject m_cylinderIndexBuffer;

  BufferObject m_triArrayBuffer;
  BufferObject m_triIndexBuffer;

  ShaderProgram m_cylinderProgram;
  Shader        m_cylinderVertexShader;
  Shader        m_cylinderFragmentShader;
};

inline const Camera& GLRenderer::camera() const
{
  return m_camera;
}

inline Camera& GLRenderer::camera()
{
  return m_camera;
}

inline Primitive::Identifier GLRenderer::hit(int x, int y) const
{
  std::map<float, Primitive::Identifier> results = hits(x, y);
  if (results.size())
    return results.begin()->second;
  return Primitive::Identifier();
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_GLRENDERER_H
