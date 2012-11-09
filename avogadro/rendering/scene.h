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
  static int colorOffset() { return sizeof(Vector3f); }
  static int textureCoordOffset()
  {
    return colorOffset() + sizeof(Vector3ub) + sizeof(unsigned char);
  }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

class AVOGADRORENDERING_EXPORT Scene
{
public:
  Scene();
  ~Scene();

  /*! Identifies the type of object a primitive represents. */
  enum PrimitiveType {
    InvalidPrimitive = -1,
    AtomPrimitive,
    BondPrimitive
  };

  /*! Used to identify the primitive during picking. */
  struct PrimitiveIdentifier {
    const Core::Molecule *molecule;
    PrimitiveType type;
    size_t index;

    PrimitiveIdentifier() : molecule(0), type(InvalidPrimitive), index(-1) {}
  };

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
                 const PrimitiveIdentifier &id);

  /*! Number of spheres in this Scene object. */
  Index sphereCount() const { return m_spheres.size() / 4; }

  /*! Get a const reference to the sphere array that can be passed to the
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<ColorTextureVertex>& spheres() const;

  /*! Get a const reference to the sphere index array that can be passed to the
   * BufferObject in order to be uploaded to the GPU.
   */
  const std::vector<unsigned int>& sphereIndices() const;

  /*!
   * \brief identifySphere Lookup the object represented by sphere i.
   * \param i Index into the spheres() vector.
   * \return PrimitiveIdentifier for
   */
  PrimitiveIdentifier identifySphere(size_t i) const;

  /*! Is the scene dirty? */
  bool dirty() const { return m_dirty; }

  /*! Mark the scene as clean (should only be done once the data is uploaded to
   * the BufferObject.
   */
  void setClean() { m_dirty = false; }

  /*! Clear the scene of all elements. */
  void clear();

private:
  std::vector<unsigned int> m_sphereIndices;
  std::vector<ColorTextureVertex> m_spheres;
  std::vector<PrimitiveIdentifier> m_sphereIdentifiers;

  bool             m_dirty;
  mutable bool     m_centerDirty;
  mutable Vector3f m_center;
  mutable float    m_radius;
};

inline const std::vector<ColorTextureVertex>& Scene::spheres() const
{
  return m_spheres;
}

inline const std::vector<unsigned int>& Scene::sphereIndices() const
{
  return m_sphereIndices;
}

inline Scene::PrimitiveIdentifier Scene::identifySphere(size_t i) const
{
  if (i < m_sphereIdentifiers.size())
    return m_sphereIdentifiers[i];
  return Scene::PrimitiveIdentifier();
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SCENE_H
