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

struct BufferObject::Private
{
  Private() : handle(0) {}
  GLenum type;
  GLuint handle;
};

BufferObject::BufferObject(ObjectType type_)
  : d(new Private), m_dirty(true)
{
  if (type_ == ARRAY_BUFFER)
    d->type = GL_ARRAY_BUFFER;
  else
    d->type = GL_ELEMENT_ARRAY_BUFFER;
}

BufferObject::~BufferObject()
{
  if (d->handle != 0)
    glDeleteBuffers(1, &d->handle);
  delete d;
}

BufferObject::ObjectType BufferObject::type() const
{
  if (d->type == GL_ARRAY_BUFFER)
    return ARRAY_BUFFER;
  else
    return ELEMENT_ARRAY_BUFFER;
}

Index BufferObject::handle() const
{
  return static_cast<Index>(d->handle);
}

bool BufferObject::upload(const std::vector<ColorNormalVertex> &array)
{
  if (d->handle == 0) {
    glGenBuffers(1, &d->handle);
    d->type = GL_ARRAY_BUFFER;
  }
  else if (d->type != GL_ARRAY_BUFFER) {
    m_error = "Trying to upload array buffer to incompatible buffer.";
    return false;
  }
  glBindBuffer(d->type, d->handle);
  glBufferData(d->type, array.size() * sizeof(ColorNormalVertex),
               static_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_dirty = false;
  return true;
}

bool BufferObject::upload(const std::vector<ColorTextureVertex> &array)
{
  if (d->handle == 0) {
    glGenBuffers(1, &d->handle);
    d->type = GL_ARRAY_BUFFER;
  }
  else if (d->type != GL_ARRAY_BUFFER) {
    m_error = "Trying to upload array buffer to incompatible buffer.";
    return false;
  }
  glBindBuffer(d->type, d->handle);
  glBufferData(d->type, array.size() * sizeof(ColorTextureVertex),
               static_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_dirty = false;
  return true;
}

bool BufferObject::upload(const std::vector<Vector2f> &array)
{
  if (d->handle == 0) {
    glGenBuffers(1, &d->handle);
    d->type = GL_ARRAY_BUFFER;
  }
  else if (d->type != GL_ARRAY_BUFFER) {
    m_error = "Trying to upload array buffer to incompatible buffer.";
    return false;
  }
  glBindBuffer(d->type, d->handle);
  glBufferData(d->type, array.size() * sizeof(Vector2f),
               static_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_dirty = false;
  return true;
}

bool BufferObject::upload(const std::vector<Vector3f> &array)
{
  if (d->handle == 0) {
    glGenBuffers(1, &d->handle);
    d->type = GL_ARRAY_BUFFER;
  }
  else if (d->type != GL_ARRAY_BUFFER) {
    m_error = "Trying to upload array buffer to incompatible buffer.";
    return false;
  }
  glBindBuffer(d->type, d->handle);
  glBufferData(d->type, array.size() * sizeof(Vector3f),
               static_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_dirty = false;
  return true;
}

bool BufferObject::upload(const std::vector<unsigned int> &array)
{
  if (d->handle == 0) {
    glGenBuffers(1, &d->handle);
    d->type = GL_ELEMENT_ARRAY_BUFFER;
  }
  else if (d->type != GL_ELEMENT_ARRAY_BUFFER) {
    m_error = "Trying to upload element array buffer to incompatible buffer.";
    return false;
  }
  glBindBuffer(d->type, d->handle);
  glBufferData(d->type, array.size() * sizeof(unsigned int),
               static_cast<const GLvoid *>(&array[0]),
               GL_STATIC_DRAW);
  m_dirty = false;
  return true;
}

bool BufferObject::bind()
{
  if (!d->handle)
    return false;

  glBindBuffer(d->type, d->handle);
  return true;
}

bool BufferObject::release()
{
  if (!d->handle)
    return false;

  glBindBuffer(d->type, 0);
  return true;
}

} // End Rendering namespace
} // End Avogadro namespace
