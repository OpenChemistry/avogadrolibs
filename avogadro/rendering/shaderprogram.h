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

#ifndef AVOGADRO_RENDERING_SHADERPROGRAM_H
#define AVOGADRO_RENDERING_SHADERPROGRAM_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

#include <string> // For member variables.
#include <vector> // For member variables.
#include <map>    // For member variables.

namespace Avogadro {
namespace Rendering {

class Shader;

/// \class ShaderProgram shaderprogram.h <avogadro/rendering/shaderprogram.h>
/// \brief The ShaderProgram uses one or more Shader objects.
/// \author Marcus D. Hanwell

/// This class creates a Vertex or Fragment shader, that can be attached to a
/// ShaderProgram in order to render geometry etc.

class AVOGADRORENDERING_EXPORT ShaderProgram
{
public:
  ShaderProgram();
  ~ShaderProgram();

  /// Attach the supplied shader to this program.
  /// \note A maximum of one Vertex shader and one Fragment shader can be
  /// attached to a shader prorgram.
  /// \return true on success.
  bool attachShader(const Shader &shader);

  /// Detach the supplied shader from this program.
  /// \note A maximum of one Vertex shader and one Fragment shader can be
  /// attached to a shader prorgram.
  /// \return true on success.
  bool detachShader(const Shader &shader);

  /// Attempt to link the shader program.
  /// \return false on failure. Query error to get the reason.
  /// \note The shaders attached to the program must have been compiled.
  bool link();

  /// Bind the program in order to use it. If the program has not been linked
  /// then link() will be called.
  bool bind();

  /// Releases the shader program from the current context.
  void release();

  /// Get the error message (empty if none) for the shader program.
  std::string error() const { return m_error; }

  bool enableAttributeArray(const std::string &name);
  bool disableAttributeArray(const std::string &name);
  // Use the VBO with the supplied offset.

  bool useAttributeArray(const std::string &name, int offset, Vector2f v);
  bool useAttributeArray(const std::string &name, int offset, Vector3f v);
  bool useAttributeArray(const std::string &name, int offset, Vector3ub v);

  // Upload data to the named attribute array
  bool setAttributeArray(const std::string &name,
                         const std::vector<unsigned short> &array);
  bool setAttributeArray(const std::string &name,
                         const std::vector<Vector2f> &array);
  bool setAttributeArray(const std::string &name,
                         const std::vector<Vector3f> &array);
  bool setAttributeArray(const std::string &name,
                         const std::vector<Vector3ub> &array);

  bool setUniformValue(const std::string &name, const Eigen::Matrix3f &matrix);
  bool setUniformValue(const std::string &name, const Eigen::Matrix4f &matrix);

/*
  addShader

  addUniform

  addVertexAttribute

  uniformExist

  link
  validate
  use

  bind */

protected:
  Index m_handle;
  Index m_vertexShader;
  Index m_fragmentShader;

  bool m_linked;

  std::string m_error;

  std::map<std::string, int> m_attributes;

private:
  int findAttributeArray(const std::string &name);
  int findUniform(const std::string &name);
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SHADERPROGRAM_H
