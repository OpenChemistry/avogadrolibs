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

/*!
 * \class Scene scene.h <avogadro/rendering/scene.h>
 * \brief The Scene contains data ready to be rendered.
 * \author Marcus D. Hanwell
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

  /*! Get the center of the points contained in this Scene. */
  Vector3f center() const;

  /*! Get the radius, which is currently just the largest of the axis-aligned
   * components of the positions.
   */
  float radius() const;

  /*!
   * Add a sphere to the scene object.
   */
  void addSphere(const Vector3f &position, const Vector3ub &color, float radius,
                 const Primitive::Identifier &id);

  /*! Get a const reference to the sphere list in this Scene object. */
  const std::vector<Sphere> spheres() const { return m_spheres; }

  /*! Number of spheres in this Scene object. */
  Index sphereCount() const { return m_spheres.size(); }

  /*! Get a const reference to the sphere array that can be passed to the
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<ColorTextureVertex>& sphereVertices() const;

  /*! Get a const reference to the sphere index array that can be passed to the
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<unsigned int>& sphereIndices() const;

  /*!
   * Add a cylinder to the Scene object. Direction must be normalized.
   */
  void addCylinder(const Vector3f &position, const Vector3f &direction,
                   float length, float radius_, const Vector3ub &color,
                   const Primitive::Identifier &id);

  /*! Get a const reference to the cylinder list in this Scene object. */
  const std::vector<Cylinder> cylinders() const { return m_cylinders; }

  /*! Number of cylinders in this Scene object. */
  Index cylinderCount() const { return m_cylinders.size(); }

  /*! Get a const reference to the cylinder vertex array that can be passed to
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<ColorNormalVertex>& cylinderVertices() const;

  /*! Get a const reference to the cylinder index array that can be passed to
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<unsigned int> &cylinderIndices() const;

  /*! Is the scene dirty? */
  bool dirty() const { return m_dirty; }

  /*! Mark the scene as clean (should only be done once the data is uploaded to
   * the BufferObject.
   */
  void setClean() { m_dirty = false; }

  /*! Clear the scene of all elements. */
  void clear();

private:
  std::vector<Sphere> m_spheres;
  std::vector<unsigned int> m_sphereIndices;
  std::vector<ColorTextureVertex> m_sphereVertices;

  std::vector<Cylinder> m_cylinders;
  std::vector<unsigned int> m_cylinderIndices;
  std::vector<ColorNormalVertex> m_cylinderVertices;

  bool             m_dirty;
  mutable bool     m_centerDirty;
  mutable Vector3f m_center;
  mutable float    m_radius;
};

inline const std::vector<ColorTextureVertex>& Scene::sphereVertices() const
{
  return m_sphereVertices;
}

inline const std::vector<unsigned int>& Scene::sphereIndices() const
{
  return m_sphereIndices;
}

inline const std::vector<ColorNormalVertex>& Scene::cylinderVertices() const
{
  return m_cylinderVertices;
}

inline const std::vector<unsigned int> &Scene::cylinderIndices() const
{
  return m_cylinderIndices;
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SCENE_H
