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

#include <map>    // For member variables.
#include <string> // For member variables.
#include <vector> // For member variables.

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
struct ColorTextureVertex
{
  Vector3f vertex;           // 12 bytes
  Vector3ub color;           //  3 bytes
  unsigned char unusedAlign; //  1 byte
  Vector2f textureCoord;     //  8 bytes
  Vector2f textureCoord2;    //  8 bytes

  ColorTextureVertex(const Vector3f& p, const Vector3ub& c, const Vector2f& t,
                     const Vector2f& t2 = Vector2f::Zero())
    : vertex(p), color(c), textureCoord(t), textureCoord2(t2)
  {}

  static int vertexOffset() { return 0; }
  static int colorOffset() { return static_cast<int>(sizeof(Vector3f)); }
  static int textureCoordOffset()
  {
    return colorOffset() +
           static_cast<int>(sizeof(Vector3ub) + sizeof(unsigned char));
  }
  static int textureCoord2Offset()
  {
    return textureCoordOffset() + static_cast<int>(sizeof(Vector2f));
  }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

/// Pack the vertex data into a contiguous array.
struct ColorNormalVertex
{
  Vector3ub color;           //  3 bytes
  unsigned char unusedAlign; //  1 byte
  Vector3f normal;           // 12 bytes
  Vector3f vertex;           // 12 bytes
  unsigned char padding[4];  //  4 bytes
  ColorNormalVertex() {}
  ColorNormalVertex(const Vector3ub& c, const Vector3f& n, const Vector3f& v)
    : color(c), normal(n), vertex(v)
  {}

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

  /**
   * Set the background color of the scene (default is black).
   */
  void setBackgroundColor(const Vector4ub& color) { m_backgroundColor = color; }

  /**
   * Get the background color of the scene.
   */
  Vector4ub backgroundColor() const { return m_backgroundColor; }

  /**
   * Mark the scene as dirty, primarily to ensure radius/center will be
   * recalculated.
   */
  void setDirty(bool dirty) { m_dirty = dirty; }

  /**
   * Has the scene been marked as dirty?
   */
  bool isDirty() const { return m_dirty; }

  /** Clear the scene of all elements. */
  void clear();

private:
  GroupNode m_rootNode;
  Vector4ub m_backgroundColor;

  mutable bool m_dirty;
  mutable Vector3f m_center;
  mutable float m_radius;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_SCENE_H
