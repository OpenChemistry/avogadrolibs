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

/// \class Buffer Object bufferobject.h <avogadro/rendering/bufferobject.h>
/// \brief Buffer object to store geometry/attribute data on the GPU.
/// \author Marcus D. Hanwell

/// This class creates GPU buffer object, and uploads the data to the GPU.

class AVOGADRORENDERING_EXPORT BufferObject
{
public:
  BufferObject();
  ~BufferObject();

  Index handle() const { return m_handle; }
  bool ready() const { return m_dirty == false; }

protected:
  Index m_handle;
  bool  m_dirty;

  std::string m_error;
};

class AVOGADRORENDERING_EXPORT ArrayBufferObject : public BufferObject
{
public:
  bool upload(const std::vector<ColorTextureVertex> &array);
  bool bind();
  bool release();
};

class AVOGADRORENDERING_EXPORT IndexBufferObject : public BufferObject
{
public:
  bool upload(const std::vector<unsigned int> &array);
  bool bind();
  bool release();
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_BUFFEROBJECT_H
