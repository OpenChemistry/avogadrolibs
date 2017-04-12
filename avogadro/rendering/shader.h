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

#ifndef AVOGADRO_RENDERING_SHADER_H
#define AVOGADRO_RENDERING_SHADER_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>

#include <string> // For member variables.

namespace Avogadro {
namespace Rendering {

/**
 * @class Shader shader.h <avogadro/rendering/shader.h>
 * @brief Vertex or Fragment shader, combined into a ShaderProgram.
 * @author Marcus D. Hanwell
 *
 * This class creates a Vertex or Fragment shader, that can be attached to a
 * ShaderProgram in order to render geometry etc.
 */

class AVOGADRORENDERING_EXPORT Shader
{
public:
  /** Available shader types. */
  enum Type
  {
    Vertex,   /**< Vertex shader */
    Fragment, /**< Fragment shader */
    Unknown   /**< Unknown (default) */
  };

  explicit Shader(Type type = Unknown, const std::string& source = "");
  ~Shader();

  /** Set the shader type. */
  void setType(Type type);

  /** Get the shader type, typically Vertex or Fragment. */
  Type type() const { return m_type; }

  /** Set the shader source to the supplied string. */
  void setSource(const std::string& source);

  /** Get the source for the shader. */
  std::string source() const { return m_source; }

  /** Get the error message (empty if none) for the shader. */
  std::string error() const { return m_error; }

  /** Get the handle of the shader. */
  Index handle() const { return m_handle; }

  /** Compile the shader.
   * @note A valid context must to current in order to compile the shader.
   */
  bool compile();

  /** Delete the shader.
   * @note This should only be done once the ShaderProgram is done with the
   * Shader.
   */
  void cleanup();

protected:
  Type m_type;
  Index m_handle;
  bool m_dirty;

  std::string m_source;
  std::string m_error;
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SHADER_H
