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
namespace Rendering {

/// \class Scene scene.h <avogadro/rendering/scene.h>
/// \brief The Scene contains data ready to be rendered.
/// \author Marcus D. Hanwell

/// A collection of geometric primitives ready for rendering. This is highly
/// targeted for fast rendering on modern OpenGL 2.1/ES 2.0 GPUs, but can also
/// be adapted and rendered using other approaches.

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
  static int textureCoordOffset() { return colorOffset() + sizeof(Vector3ub) + sizeof(unsigned char); }
}; // 32 bytes total size - 16/32/64 are ideal for alignment.

class AVOGADRORENDERING_EXPORT Scene
{
public:
  Scene();
  ~Scene();

  Vector3f center() const;
  float radius() const;

  void addSphere(const Vector3f &position, const Vector3ub &color, float radius);
  Index sphereCount() const { return m_spherePositions.size() / 4; }
  const float * spherePositionPointer(Index offset) const;
  const float * sphereRadiiPointer(Index offset) const;
  const unsigned char * sphereColorPointer(Index offset) const;

  std::vector<unsigned int> m_sphereIndices;

  std::vector<ColorTextureVertex> m_spheres;

  std::vector<Vector3f> m_spherePositions;
  std::vector<Vector2f> m_sphereRadii;
  std::vector<Vector3ub> m_sphereColors;

  mutable bool     m_centerDirty;
  mutable Vector3f m_center;
  mutable float    m_radius;
};

inline const float * Scene::spherePositionPointer(Index offset) const
{
  return m_spherePositions[offset * 4].data();
}

inline const float * Scene::sphereRadiiPointer(Index offset) const
{
  return m_sphereRadii[offset * 4].data();
}

inline const unsigned char * Scene::sphereColorPointer(Index offset) const
{
  return m_sphereColors[offset * 4].data();
}

} // End Rendering namespace
} // End Avogadro namespace

#endif // AVOGADRO_RENDERING_SCENE_H
