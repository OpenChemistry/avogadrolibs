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
  enum ObjectType {
    ARRAY_BUFFER,
    ELEMENT_ARRAY_BUFFER
  };

  BufferObject(ObjectType type = ARRAY_BUFFER);
  ~BufferObject();

  /** Get the type of the buffer object. */
  ObjectType type() const;

  /** Get the handle of the buffer object. */
  Index handle() const;

  /** Determine if the buffer object is ready to be used. */
  bool ready() const { return m_dirty == false; }

  /** Upload data to the buffer object. The buffer must be an ARRAY_BUFFER
   * or uninitialized. */
  bool upload(const std::vector<ColorNormalVertex> &array);

  /** Upload data to the buffer object. The buffer must be an ARRAY_BUFFER
   * or uninitialized. */
  bool upload(const std::vector<ColorTextureVertex> &array);

  /** Upload data to the buffer object. The buffer must be an ARRAY_BUFFER
   * or uninitialized. */
  bool upload(const std::vector<Vector2f> &array);

  /** Upload data to the buffer object. The buffer must be an ARRAY_BUFFER
   * or uninitialized. */
  bool upload(const std::vector<Vector3f> &array);

  /** Upload data to the buffer object. The buffer must be an
   * ELEMENT_ARRAY_BUFFER or uninitialized. */
  bool upload(const std::vector<unsigned int> &array);

  /** Bind the buffer object ready for rendering.
   * @note Only one ARRAY_BUFFER and one ELEMENT_ARRAY_BUFFER may be bound at
   * any time. */
  bool bind();

  /** Release the buffer. This should be done after rendering is complete. */
  bool release();

  /** Return a string describing errors. */
  std::string error() const { return m_error; }

private:
  struct Private;
  Private *d;
  bool  m_dirty;

  std::string m_error;
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_BUFFEROBJECT_H
