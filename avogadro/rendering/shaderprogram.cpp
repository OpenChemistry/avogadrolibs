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

#include "shaderprogram.h"

#include "shader.h"
#include "avogadrogl.h"

#include <avogadro/core/types.h>

namespace Avogadro {
namespace Rendering {

namespace {
inline GLenum convertType(Type type)
{
  switch (type) {
  default:
  case UCharType:
    return GL_UNSIGNED_BYTE;
  case CharType:
    return GL_BYTE;
  case ShortType:
    return GL_SHORT;
  case UShortType:
    return GL_UNSIGNED_SHORT;
  case IntType:
    return GL_INT;
  case UIntType:
    return GL_UNSIGNED_INT;
  case FloatType:
    return GL_FLOAT;
  case DoubleType:
    return GL_DOUBLE;
  }
}
} // end anon namespace

ShaderProgram::ShaderProgram() : m_handle(0), m_vertexShader(0),
  m_fragmentShader(0), m_linked(false)
{
}

ShaderProgram::~ShaderProgram()
{
}

bool ShaderProgram::attachShader(const Shader &shader)
{
  if (shader.handle() == 0) {
    m_error = "Shader object was not initialized, cannot attach it.";
    return false;
  }
  if (shader.type() == Shader::Unknown) {
    m_error = "Shader object is of type Unknown and cannot be used.";
    return false;
  }

  if (m_handle == 0) {
    GLuint handle_ = glCreateProgram();
    if (handle_ == 0) {
      m_error = "Could not create shader program.";
      return false;
    }
    m_handle = static_cast<Index>(handle_);
    m_linked = false;
  }

  if (shader.type() == Shader::Vertex) {
    if (m_vertexShader != 0) {
      glDetachShader(static_cast<GLuint>(m_handle),
                     static_cast<GLuint>(m_vertexShader));
      m_vertexShader = shader.handle();
    }
  }
  else if (shader.type() == Shader::Fragment) {
    if (m_fragmentShader != 0) {
      glDetachShader(static_cast<GLuint>(m_handle),
                     static_cast<GLuint>(m_fragmentShader));
      m_fragmentShader = shader.handle();
    }
  }
  else {
    m_error = "Unknown shader type encountered - this should not happen.";
    return false;
  }

  glAttachShader(static_cast<GLuint>(m_handle),
                 static_cast<GLuint>(shader.handle()));
  m_linked = false;
  return true;
}

bool ShaderProgram::detachShader(const Shader &shader)
{
  if (shader.handle() == 0) {
    m_error = "Shader object was not initialized, cannot attach it.";
    return false;
  }
  if (shader.type() == Shader::Unknown) {
    m_error = "Shader object is of type Unknown and cannot be used.";
    return false;
  }
  if (m_handle == 0) {
    m_error = "This shader prorgram has not been initialized yet.";
  }

  switch (shader.type()) {
  case Shader::Vertex:
    if (m_vertexShader != shader.handle()) {
      m_error = "The supplied shader was not attached to this program.";
      return false;
    }
    else {
      glDetachShader(static_cast<GLuint>(m_handle),
                     static_cast<GLuint>(shader.handle()));
      m_vertexShader = 0;
      m_linked = false;
      return true;
    }
  case Shader::Fragment:
    if (m_fragmentShader != shader.handle()) {
      m_error = "The supplied shader was not attached to this program.";
      return false;
    }
    else {
      glDetachShader(static_cast<GLuint>(m_handle),
                     static_cast<GLuint>(shader.handle()));
      m_fragmentShader = 0;
      m_linked = false;
      return true;
    }
  default:
    return false;
  }
}

bool ShaderProgram::link()
{
  if (m_linked)
    return true;

  if (m_handle == 0) {
    m_error = "Program has not been initialized, and/or does not have shaders.";
    return false;
  }

  GLint isCompiled;
  glLinkProgram(static_cast<GLuint>(m_handle));
  glGetProgramiv(static_cast<GLuint>(m_handle), GL_LINK_STATUS, &isCompiled);
  if (isCompiled == 0) {
    GLint length(0);
    glGetShaderiv(static_cast<GLuint>(m_handle), GL_INFO_LOG_LENGTH, &length);
    if (length > 1) {
      char *logMessage = new char[length];
      glGetShaderInfoLog(static_cast<GLuint>(m_handle), length, NULL, logMessage);
      m_error = logMessage;
      delete[] logMessage;
    }
    return false;
  }
  m_linked = true;
  m_attributes.clear();
  return true;
}

bool ShaderProgram::bind()
{
  if (!m_linked && !link())
    return false;

  glUseProgram(static_cast<GLuint>(m_handle));
  return true;
}

void ShaderProgram::release()
{
  glUseProgram(0);
}

bool ShaderProgram::enableAttributeArray(const std::string &name)
{
  GLint location = static_cast<GLint>(findAttributeArray(name));
  if (location == -1) {
    m_error = "Could not enable attribute " + name + ". No such attribute.";
    return false;
  }
  glEnableVertexAttribArray(location);
  return true;
}

bool ShaderProgram::disableAttributeArray(const std::string &name)
{
  GLint location = static_cast<GLint>(findAttributeArray(name));
  if (location == -1) {
    m_error = "Could not disable attribute " + name + ". No such attribute.";
    return false;
  }
  glDisableVertexAttribArray(location);
  return true;
}

#define BUFFER_OFFSET(i) ((char *)NULL + (i))

bool ShaderProgram::useAttributeArray(const std::string &name, int offset,
                                      int stride, Type elementType,
                                      int elementTupleSize,
                                      NormalizeOption normalize)
{
  GLint location = static_cast<GLint>(findAttributeArray(name));
  if (location == -1) {
    m_error = "Could not use attribute " + name + ". No such attribute.";
    return false;
  }
  glVertexAttribPointer(location, elementTupleSize, convertType(elementType),
                        normalize == Normalize ? GL_TRUE : GL_FALSE, stride,
                        BUFFER_OFFSET(offset));
  return true;
}

bool ShaderProgram::setUniformValue(const std::string &name, int i)
{
  GLint location = static_cast<GLint>(findUniform(name));
  if (location == -1) {
    m_error = "Could not set uniform " + name + ". No such uniform.";
    return false;
  }
  glUniform1i(location, static_cast<GLint>(i));
  return true;
}

bool ShaderProgram::setUniformValue(const std::string &name, float f)
{
  GLint location = static_cast<GLint>(findUniform(name));
  if (location == -1) {
    m_error = "Could not set uniform " + name + ". No such uniform.";
    return false;
  }
  glUniform1f(location, static_cast<GLfloat>(f));
  return true;
}

bool ShaderProgram::setUniformValue(const std::string &name,
                                    const Eigen::Matrix3f &matrix)
{
  GLint location = static_cast<GLint>(findUniform(name));
  if (location == -1) {
    m_error = "Could not set uniform " + name + ". No such uniform.";
    return false;
  }
  glUniformMatrix3fv(location, 1, GL_FALSE,
                     static_cast<const GLfloat *>(matrix.data()));
  return true;
}

bool ShaderProgram::setUniformValue(const std::string &name,
                                    const Eigen::Matrix4f &matrix)
{
  GLint location = static_cast<GLint>(findUniform(name));
  if (location == -1) {
    m_error = "Could not set uniform " + name + ". No such uniform.";
    return false;
  }
  glUniformMatrix4fv(location, 1, GL_FALSE,
                     static_cast<const GLfloat *>(matrix.data()));
  return true;
}

bool ShaderProgram::setUniformValue(const std::string &name,
                                    const Vector3ub &v)
{
  GLint location = static_cast<GLint>(findUniform(name));
  if (location == -1) {
    m_error = "Could not set uniform " + name + ". No such uniform.";
    return false;
  }
  Vector3f colorf(v.cast<float>() * (1.0f / 255.0f));
  glUniform3fv(location, 1, colorf.data());
  return true;
}

bool ShaderProgram::setAttributeArrayInternal(
    const std::string &name, void *buffer, Avogadro::Type type, int tupleSize,
    ShaderProgram::NormalizeOption normalize)
{
  if (type == Avogadro::UnknownType) {
    m_error = "Unrecognized data type for attribute " + name + ".";
    return false;
  }
  GLint location = static_cast<GLint>(findAttributeArray(name));
  if (location == -1) {
    m_error = "Could not set attribute " + name + ". No such attribute.";
    return false;
  }
  const GLvoid *data = static_cast<const GLvoid *>(buffer);
  glVertexAttribPointer(location, tupleSize, convertType(type),
                        normalize == Normalize ? GL_TRUE : GL_FALSE, 0, data);
  return true;
}

inline int ShaderProgram::findAttributeArray(const std::string &name)
{
  if (name.empty() || !m_linked)
    return -1;
  const GLchar *namePtr = static_cast<const GLchar *>(name.c_str());
  GLint location =
      static_cast<int>(glGetAttribLocation(static_cast<GLuint>(m_handle),
                                           namePtr));
  if (location == -1) {
    m_error = "Specified attribute not found in current shader program: ";
    m_error += name;
  }

  return location;
}

inline int ShaderProgram::findUniform(const std::string &name)
{
  if (name.empty() || !m_linked)
    return -1;
  const GLchar *namePtr = static_cast<const GLchar *>(name.c_str());
  GLint location =
      static_cast<int>(glGetUniformLocation(static_cast<GLuint>(m_handle),
                                            namePtr));
  if (location == -1)
    m_error = "Uniform " + name + " not found in current shader program.";

  return location;
}

} // End Rendering namespace
} // End Avogadro namespace
