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

#ifndef AVOGADRO_RENDERING_BUFFEROBJECT_H
#define AVOGADRO_RENDERING_BUFFEROBJECT_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>

#include "scene.h"

#include <string> // For member variables.
#include <vector> // For API.

namespace Avogadro {
namespace Rendering {

/**
 * @class BufferObject bufferobject.h <avogadro/rendering/bufferobject.h>
 * @brief Buffer object to store geometry/attribute data on the GPU.
 * @author Marcus D. Hanwell
 *
 * This class creates GPU buffer object, and uploads the data to the GPU.
 */

class AVOGADRORENDERING_EXPORT BufferObject
{
public:
  enum ObjectType
  {
    ArrayBuffer,
    ElementArrayBuffer
  };

  BufferObject(ObjectType type = ArrayBuffer);
  ~BufferObject();

  /** Get the type of the buffer object. */
  ObjectType type() const;

  /** Get the handle of the buffer object. */
  Index handle() const;

  /** Determine if the buffer object is ready to be used. */
  bool ready() const { return m_dirty == false; }

  /**
   * Upload data to the buffer object. The BufferObject::type() must match
   * @a type or be uninitialized.
   *
   * The ContainerT type must have tightly packed values of
   * ContainerT::value_type accessible by reference via ContainerT::operator[].
   * Additionally, the standard size() and empty() methods must be implemented.
   * The std::vector and Avogadro::Core::Array classes are examples of such
   * supported containers.
   */
  template <class ContainerT>
  bool upload(const ContainerT& array, ObjectType type);

  /** Bind the buffer object ready for rendering.
   * @note Only one ARRAY_BUFFER and one ELEMENT_ARRAY_BUFFER may be bound at
   * any time. */
  bool bind();

  /** Release the buffer. This should be done after rendering is complete. */
  bool release();

  /** Return a string describing errors. */
  std::string error() const { return m_error; }

private:
  bool uploadInternal(const void* buffer, size_t size, ObjectType objectType);

  struct Private;
  Private* d;
  bool m_dirty;

  std::string m_error;
};

template <class ContainerT>
inline bool BufferObject::upload(const ContainerT& array,
                                 BufferObject::ObjectType objectType)
{
  if (array.empty()) {
    m_error = "Refusing to upload empty array.";
    return false;
  }
  return uploadInternal(&array[0],
                        array.size() * sizeof(typename ContainerT::value_type),
                        objectType);
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_BUFFEROBJECT_H
