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

#include "bufferobject.h"

#include "avogadrogl.h"

namespace Avogadro {
namespace Rendering {

BufferObject::BufferObject() : m_handle(0), m_dirty(true)
{
}

BufferObject::~BufferObject()
{
}

bool ArrayBufferObject::upload(const std::vector<ColorTextureVertex> &array)
{
  GLuint handle_(0);
  glGenBuffers(1, &handle_);
  glBindBuffer(GL_ARRAY_BUFFER, handle_);
  glBufferData(GL_ARRAY_BUFFER, array.size() * sizeof(ColorTextureVertex),
               reinterpret_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_handle = static_cast<Index>(handle_);
  m_dirty = false;
  return true;
}

bool ArrayBufferObject::bind()
{
  if (!m_handle)
    return false;

  glBindBuffer(GL_ARRAY_BUFFER, static_cast<GLuint>(m_handle));
  return true;
}

bool ArrayBufferObject::release()
{
  if (!m_handle)
    return false;

  glBindBuffer(GL_ARRAY_BUFFER, 0);
  return true;
}

bool IndexBufferObject::upload(const std::vector<unsigned int> &array)
{
  GLuint handle_(0);
  glGenBuffers(1, &handle_);
  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, handle_);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, array.size() * sizeof(unsigned int),
               reinterpret_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_handle = static_cast<Index>(handle_);
  m_dirty = false;
  return true;
}

bool IndexBufferObject::bind()
{
  if (!m_handle)
    return false;

  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, static_cast<GLuint>(m_handle));
  return true;
}

bool IndexBufferObject::release()
{
  if (!m_handle)
    return false;

  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
  return true;
}

} // End Rendering namespace
} // End Avogadro namespace
