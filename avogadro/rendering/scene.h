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

#ifndef AVOGADRO_RENDERING_SCENE_H
#define AVOGADRO_RENDERING_SCENE_H

#include "avogadrorenderingexport.h"

#include "groupnode.h"
#include "primitive.h"

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/vector.h>

#include <string> // For member variables.
#include <vector> // For member variables.
#include <map>    // For member variables.

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Rendering {

/**
 * @class Scene scene.h <avogadro/rendering/scene.h>
 * @brief The Scene contains data ready to be rendered.
 * @author Marcus D. Hanwell
 *
 * A collection of geometric primitives ready for rendering. This is highly
 * targeted for fast rendering on modern OpenGL 2.1/ES 2.0 GPUs, but can also
 * be adapted and rendered using other approaches.
 */

/// Pack the vertex data into a contiguous array.
struct ColorTextureVertex {
  Vector3f vertex;           // 12 bytes
  Vector3ub color;           //  3 bytes
  unsigned char unusedAlign; //  1 byte
  Vector2f textureCoord;     //  8 bytes
  Vector2f padding;          //  8 bytes

  ColorTextureVertex(const Vector3f &p, const Vector3ub &c, const Vector2f &t)
    : vertex(p), color(c), textureCoord(t)
  {
  }

  static int vertexOffset() { return 0; }
  static int colorOffset() { return static_cast<int>(sizeof(Vector3f)); }
  static int textureCoordOffset()
  {
    return colorOffset() +
        static_cast<int>(sizeof(Vector3ub) + sizeof(unsigned char));
  }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

/// Pack the vertex data into a contiguous array.
struct ColorNormalVertex {
  Vector3ub color;           //  3 bytes
  unsigned char unusedAlign; //  1 byte
  Vector3f normal;           // 12 bytes
  Vector3f vertex;           // 12 bytes
  unsigned char padding[4];  //  4 bytes

  ColorNormalVertex(const Vector3ub &c, const Vector3f &n, const Vector3f &v)
    : color(c), normal(n), vertex(v) {}

  static int colorOffset() { return 0; }
  static int normalOffset()
  {
    return static_cast<int>(sizeof(Vector3ub) + sizeof(unsigned char));
  }
  static int vertexOffset()
  {
    return normalOffset() + static_cast<int>(sizeof(Vector3f));
  }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

class AVOGADRORENDERING_EXPORT Scene
{
public:
  Scene();
  ~Scene();

  /** Get the center of the points contained in this Scene. */
  Vector3f center();

  /** Get the radius, which is currently just the largest of the axis-aligned
   * components of the positions.
   */
  float radius();

  /**
   * Get the root node of the scene.
   */
  GroupNode& rootNode() { return m_rootNode; }
  const GroupNode& rootNode() const { return m_rootNode; }

  /** Is the scene dirty? */
  bool dirty() const { return m_dirty; }

  /** Mark the scene as clean (should only be done once the data is uploaded to
   * the BufferObject.
   */
  void setClean() { m_dirty = false; }

  /** Clear the scene of all elements. */
  void clear();

private:
  GroupNode m_rootNode;

  bool             m_dirty;
  mutable bool     m_centerDirty;
  mutable Vector3f m_center;
  mutable float    m_radius;
};

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SCENE_H
