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

#ifndef AVOGADRO_RENDERING_PRIMITIVE_H
#define AVOGADRO_RENDERING_PRIMITIVE_H

#include <avogadro/core/vector.h>

namespace Avogadro {
namespace Rendering {

/** Identifies the type of object a primitive represents. */
enum Type
{
  InvalidType = -1,
  AtomType,
  BondType
};

/** Used to identify the primitive during picking. */
struct Identifier
{
  Identifier() : molecule(0), type(InvalidType), index(MaxIndex) {}

  bool operator==(const Identifier& other) const
  {
    return molecule == other.molecule && type == other.type &&
           index == other.index;
  }

  bool operator!=(const Identifier& other) const { return !operator==(other); }

  bool isValid() const { return type != InvalidType && molecule != nullptr; }

  const void* molecule;
  Type type;
  Index index;
};

class Primitive
{
public:
  /** Identifies the type of object a primitive represents. */
  enum Type
  {
    Invalid = -1,
    Atom,
    Bond
  };

  /** Used to identify the primitive during picking. */
  struct Identifier
  {
    Identifier() : molecule(0), type(Invalid), index(MaxIndex) {}

    bool operator==(const Identifier& other) const
    {
      return molecule == other.molecule && type == other.type &&
             index == other.index;
    }

    bool operator!=(const Identifier& other) const
    {
      return !operator==(other);
    }

    bool isValid() const { return type != Invalid; }

    const void* molecule;
    Type type;
    Index index;
  };

  Primitive(Identifier id, const Vector3ub& color_)
    : m_identifier(id), m_color(color_)
  {
  }

  Identifier identifier() const { return m_identifier; }
  void setIdentifier(Identifier id) { m_identifier = id; }

  const Vector3ub& color() const { return m_color; }
  void setColor(const Vector3ub& c) { m_color = c; }

private:
  Identifier m_identifier;
  Vector3ub m_color;
};

class Sphere : public Primitive
{
public:
  Sphere(const Vector3f& position_, float radius_, Primitive::Identifier id,
         const Vector3ub& color_)
    : Primitive(id, color_), m_position(position_), m_radius(radius_)
  {
  }

  const Vector3f& position() const { return m_position; }
  void setPosition(const Vector3f& pos) { m_position = pos; }

  float radius() const { return m_radius; }
  void setRadius(float r) { m_radius = r; }

private:
  Vector3f m_position;
  float m_radius;
};

class Cylinder : public Primitive
{
public:
  /// Direction must be normalized
  Cylinder(const Vector3f& position_, const Vector3f& direction_, float length_,
           float radius_, Primitive::Identifier id, const Vector3ub& color_)
    : Primitive(id, color_), m_position(position_), m_direction(direction_),
      m_length(length_), m_radius(radius_)
  {
  }

  const Vector3f& position() const { return m_position; }
  void setPosition(const Vector3f& pos) { m_position = pos; }

  const Vector3f& direction() const { return m_direction; }
  void setDirection(const Vector3f& dir) { m_direction = dir; }

  float length() const { return m_length; }
  void setLength(float l) { m_length = l; }

  float radius() const { return m_radius; }
  void setRadius(float r) { m_radius = r; }

private:
  Vector3f m_position;
  Vector3f m_direction;
  float m_length;
  float m_radius;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_PRIMITIVE_H
