/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MESH_H
#define AVOGADRO_CORE_MESH_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "array.h"
#include "color3f.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

class Molecule;
class Mutex;

/**
 * @class Mesh mesh.h <avogadro/core/mesh.h>
 * @brief Encapsulation of a triangular mesh that makes up a surface.
 * @author Marcus D. Hanwell
 *
 * The Mesh class is a data container that provides a Mesh object. All
 * meshes should be owned by a Molecule. It should also be removed by the
 * Molecule that owns it. Meshes encapsulate triangular meshes that can also
 * have colors associated with each vertex.
 */

class MeshPrivate;
class AVOGADROCORE_EXPORT Mesh
{
public:
  /**
   * Constructor.
   */
  Mesh();

  /**
   * Copy constructor
   */
  Mesh(const Mesh& other);

  /**
   * Destructor.
   */
  ~Mesh();

  /**
   * Reserve the expected space for the mesh. This causes all member array
   * storage to call the reserve function with the number specified.
   * @param size Expected size of the mesh.
   * @param colors Should the colors array reserve this space too? Defaults
   * to false.
   * @return True on success.
   */
  bool reserve(unsigned int size, bool colors = false);

  /**
   * This function allows long running calculations to mark the mesh as in
   * progress.
   * @param stable Indicate that the Mesh is currently being modified.
   */
  void setStable(bool stable);

  /**
   * Indicate whether the Mesh is complete or currently being modified. In
   * general using Mesh values from an unstable Mesh is not advisable.
   * @return True if the Mesh is complete, false if it is being modified.
   */
  bool stable();

  /**
   * Set the iso value that was used to generate the Mesh.
   */
  void setIsoValue(float value) { m_isoValue = value; }

  /**
   * @return The iso value used to generate the Mesh.
   */
  float isoValue() const { return m_isoValue; }

  /**
   * Set the unique id of the other Mesh if this Mesh is part of a pair.
   */
  void setOtherMesh(unsigned int other) { m_other = other; }

  /**
   * @return The unique id of the other Mesh if this is part of a pair.
   */
  unsigned int otherMesh() const { return m_other; }

  /**
   * Set the unique id of the Cube the Mesh was generated from.
   */
  void setCube(unsigned int cube_) { m_cube = cube_; }

  /**
   * @return The unique id of the Cube the Mesh was generated from.
   */
  unsigned int cube() const { return m_cube; }

  /**
   * @return Array containing all of the vertices in a one dimensional array.
   */
  const Core::Array<Vector3f>& vertices() const;

  /**
   * @return The number of vertices.
   */
  unsigned int numVertices() const
  {
    return static_cast<unsigned int>(m_vertices.size());
  }

  /**
   * @return Pointer to the first vertex of the specified triangle.
   */
  const Vector3f* vertex(int n) const;

  /**
   * Clear the vertices vector and assign new values.
   */
  bool setVertices(const Core::Array<Vector3f>& values);

  /**
   * Add one or more vertices, i.e., the array is expected to be of length
   * 3 x n where n is an integer.
   */
  bool addVertices(const Core::Array<Vector3f>& values);

  /**
   * @return Array containing all of the normals in a one-dimensional array.
   */
  const Core::Array<Vector3f>& normals() const;

  /**
   * @return The number of normals.
   */
  unsigned int numNormals() const
  {
    return static_cast<unsigned int>(m_normals.size());
  }

  /**
   * @return Pointer to the first normal of the specified triangle.
   */
  const Vector3f* normal(int n) const;

  /**
   * Clear the normals array and assign new values.
   */
  bool setNormals(const Core::Array<Vector3f>& values);

  /**
   * Add one or more normals, i.e., the array is expected to be of length
   * 3 x n where n is an integer.
   */
  bool addNormals(const Core::Array<Vector3f>& values);

  /**
   * @return Array containing all of the colors in a one-dimensional array.
   */
  const Core::Array<Color3f>& colors() const;

  /**
   * @return Pointer to the first color of the specified triangle.
   */
  const Color3f* color(int n) const;

  /**
   * Clear the colors array and assign new values.
   */
  bool setColors(const Core::Array<Color3f>& values);

  /**
   * Add one or more normals, i.e., the array is expected to be of length
   * 3 x n where n is an integer.
   */
  bool addColors(const Core::Array<Color3f>& values);

  /**
   * Sanity checking function - is the mesh sane?
   * @return True if the Mesh object is sane and composed of the right number
   * of elements.
   */
  bool valid() const;

  /**
   * Clear all mesh data.
   * @return True on success.
   */
  bool clear();

  /**
   * Overloaded operator.
   */
  Mesh& operator=(const Mesh& other);

  /**
   * Set the name of the Mesh.
   */
  void setName(const std::string& name_) { m_name = name_; }

  /**
   * @return The name of the Mesh.
   */
  std::string name() const { return m_name; }

  /**
   * Provides locking.
   */
  Mutex* lock() const { return m_lock; }

  /**
   * Applies Laplacian smoothing.
   * @param iterationCount number of smoothing passes to make.
   */
  void smooth(int iterationCount = 6);

  friend class Molecule;

private:
  Core::Array<Vector3f> m_vertices;
  Core::Array<Vector3f> m_normals;
  Core::Array<Color3f> m_colors;
  std::string m_name;
  bool m_stable;
  float m_isoValue;
  unsigned int m_other; // Unique id of the other mesh if this is part of a pair
  unsigned int m_cube;  // Unique id of the cube this mesh was generated from
  Mutex* m_lock;
};

} // End namespace Core
} // End namespace Avogadro

#endif // AVOGADRO_CORE_MESH_H
