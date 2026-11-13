/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CUBE_H
#define AVOGADRO_CORE_CUBE_H

#include "avogadrocoreexport.h"

#include "matrix.h"
#include "vector.h"

#include <array>
#include <vector>

namespace Avogadro::Core {

class Molecule;
class Mutex;

/**
 * @class Cube cube.h <avogadro/core/cube.h>
 * @brief Provide a data structure for regularly spaced 3D grids.
 * @author Marcus D. Hanwell
 * @author Perminder Singh
 */

class AVOGADROCORE_EXPORT Cube
{
public:
  Cube();
  ~Cube();

  /**
   * \enum Type
   * Different Cube types relating to the data
   */
  enum Type
  {
    VdW,
    SolventAccessible,
    SolventExcluded,
    ESP,
    ElectronDensity,
    SpinDensity,
    MO,
    FromFile,
    None
  };

  /**
   * @return The position of grid point (0, 0, 0), the origin of the grid.
   * For a skewed grid this is one corner of the cell, not the minimum
   * coordinate of the cube; see boundingBox().
   */
  Vector3 min() const { return m_min; }

  /**
   * @return The position of the far corner of the grid, grid point
   * (nx - 1, ny - 1, nz - 1). For a skewed grid this is not the maximum
   * coordinate of the cube; see boundingBox().
   */
  Vector3 max() const { return m_max; }

  /**
   * @return The length of the step along each grid axis. For a grid whose
   * steps lie along x, y and z (isAxisAligned()) this is the diagonal of the
   * step matrix, including any negative sign. For a skewed grid it is the
   * norm of each step vector (always positive).
   */
  Vector3 spacing() const { return m_spacing; }

  /**
   * The step matrix S: its columns are the step vectors along the grid
   * indices i, j and k, in the same units as min(). The position of grid
   * point (i, j, k) is min() + S * (i, j, k)^T. The data is stored with k
   * (the third axis) changing fastest, as ever.
   * @return The step matrix; diag(spacing) for a grid set with an
   * axis-aligned setLimits() overload.
   */
  Matrix3 steps() const { return m_steps; }

  /**
   * @return True if the step matrix has exactly zero off-diagonal elements,
   * i.e., every grid axis runs along x, y or z. No tolerance is applied, so
   * the axis-aligned code paths give bit-identical results to a diagonal
   * spacing; a file that writes a tiny nonzero off-diagonal element is
   * treated as skewed.
   */
  bool isAxisAligned() const { return m_axisAligned; }

  /**
   * Computes the axis-aligned bounding box of the eight corners of the grid.
   * Use this rather than min() and max() whenever a coordinate range is
   * needed, as those are only the extremes of an axis-aligned, positively
   * stepped grid.
   * @param lo Receives the lowest x, y and z of any corner.
   * @param hi Receives the highest x, y and z of any corner.
   */
  void boundingBox(Vector3& lo, Vector3& hi) const;

  /**
   * @return The x, y and z dimensions of the cube.
   */
  Vector3i dimensions() const { return m_points; }

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param max The maximum point in the cube.
   * @param points The number of (integer) points in the cube.
   * @return False, leaving the cube unchanged, if any axis has fewer than two
   * points (the spacing would be undefined), the total point count exceeds
   * INT_MAX, or min or max is not finite.
   */
  bool setLimits(const Vector3& min, const Vector3& max,
                 const Vector3i& points);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param max The maximum point in the cube.
   * @param spacing The interval between points in the cube.
   * @return False, leaving the cube unchanged, if spacing is not positive and
   * finite or the resulting grid has fewer than two points on any axis.
   */
  bool setLimits(const Vector3& min, const Vector3& max, float spacing);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param dim The integer dimensions of the cube in x, y and z.
   * @param spacing The interval between points in the cube.
   * @return False, leaving the cube unchanged, if any dimension is below one,
   * the total point count exceeds INT_MAX, or spacing is not positive and
   * finite.
   */
  bool setLimits(const Vector3& min, const Vector3i& dim, float spacing);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param dim The integer dimensions of the cube in x, y and z.
   * @param spacing The interval between points in the cube.
   * @return False, leaving the cube unchanged, if any dimension is below one,
   * the total point count exceeds INT_MAX, or any spacing component is not
   * positive and finite.
   */
  bool setLimits(const Vector3& min, const Vector3i& dim,
                 const Vector3& spacing);

  /**
   * Set the limits of the cube from a full step matrix, which allows skewed
   * (triclinic or hexagonal) grids.
   * @param origin The position of grid point (0, 0, 0).
   * @param dim The integer dimensions of the cube along i, j and k.
   * @param steps The step matrix; its columns are the step vectors along i, j
   * and k. The grid point (i, j, k) is at origin + steps * (i, j, k)^T.
   * @return False, leaving the cube unchanged, if any dimension is below one,
   * the total point count exceeds INT_MAX, origin or steps is not finite, or
   * steps is singular (|det| no larger than 1e-9 times the product of the
   * three column lengths).
   */
  bool setStepLimits(const Vector3& origin, const Vector3i& dim,
                     const Matrix3& steps);

  /**
   * @return True if @p steps can be used as a step matrix: it is finite and
   * its columns are linearly independent (|det| larger than 1e-9 times the
   * product of the three column lengths, so the test does not depend on the
   * unit or the grid spacing). This is the test setStepLimits() applies.
   */
  static bool validSteps(const Matrix3& steps);

  /**
   * Set the limits of the cube - copy the limits of an existing Cube.
   * @param cube Existing Cube to copy the limits from.
   * @return False, leaving this cube unchanged, if @p cube has no points.
   */
  bool setLimits(const Cube& cube);

  /**
   * Set the limits of the cube.
   * @param mol Molecule to take limits from
   * @param spacing The spacing of the regular grid
   * @param padding Padding around the molecule
   */
  bool setLimits(const Molecule& mol, float spacing, float padding);

  /**
   * @return Pointer to the vector containing all the data in a one-dimensional
   * array.
   */
  std::vector<float>* data();
  const std::vector<float>* data() const;

  /**
   * Set the values in the cube to those passed in the vector.
   */
  bool setData(const std::vector<float>& values);

  /**
   * Adds the values in the cube to those passed in the vector.
   */
  bool addData(const std::vector<float>& values);

  /**
   * @return Const iterator to the beginning of a specific row in the cube data.
   */
  std::vector<float>::const_iterator getRowIter(int j, int k) const;

  /**
   * @return Index of the point closest to the position supplied.
   * @param pos Position to get closest index for.
   */
  unsigned int closestIndex(const Vector3& pos) const;

  /**
   * @param pos Position to get closest index for.
   * @return The i, j, k index closest to the position supplied.
   */
  Vector3i indexVector(const Vector3& pos) const;

  /**
   * @param index Index to be translated to a position.
   * @return Position of the given index.
   */
  Vector3 position(unsigned int index) const;

  /**
   * This function is very quick as it just returns the value at the point.
   * @return Cube value at the integer point i, j, k.
   */
  float value(int i, int j, int k) const;

  /**
   * This function is very quick as it just returns the value at the point.
   * @return Cube value at the integer point pos.
   */
  float value(const Vector3i& pos) const;

  /**
   * This function uses trilinear interpolation to find the value at points
   * between those specified in the cube.
   * @return Cube value at the specified position.
   * @warning This function is quite computationally expensive and should be
   * avoided where possible.
   */
  float valuef(const Vector3f& pos) const;

  /**
   * This function uses trilinear interpolation to find the value at points
   * between those specified in the cube.
   * @return Cube value at the specified position.
   * @warning This function is quite computationally expensive and should be
   * avoided where possible.
   */
  float value(const Vector3& pos) const;

  /**
   * Sets the value at the specified point in the cube.
   * @param i x component of the position.
   * @param j y component of the position.
   * @param k z component of the position.
   * @param value Value at the specified position.
   */
  bool setValue(unsigned int i, unsigned int j, unsigned int k, float value);

  /**
   * Sets the value at the specified index in the cube.
   * @param i 1-dimensional index of the point to set in the cube.
   */
  bool setValue(unsigned int i, float value);

  /**
   * Sets all indices in the cube to the specified value.
   * @param value Value to fill the cube with.
   */
  void fill(float value);

  /**
   * Sets all indices in a Z stripe of the cube to the specified value.
   * @param i x component of the position.
   * @param j y component of the position.
   * @param kfirst first z position to fill.
   * @param klast last z position to fill.
   * @param value Value to fill the stripe with.
   */
  bool fillStripe(unsigned int i, unsigned int j, unsigned int kfirst,
                  unsigned int klast, float value);

  /**
   * @return The minimum value at any point in the Cube.
   */
  float minValue() const { return m_minValue; }

  /**
   * @return The maximum value at any point in the Cube.
   */
  float maxValue() const { return m_maxValue; }

  void setName(const std::string& name_) { m_name = name_; }
  std::string name() const { return m_name; }

  void setCubeType(Type type) { m_cubeType = type; }
  Type cubeType() const { return m_cubeType; }

  /**
   * Provides locking.
   */
  Mutex* lock() const { return m_lock; }

  /**
   * Compute the gradient of the cube's values at a specific point, using
   * central differences (one-sided differences at the edges of the cube).
   * The vector points toward increasing values, i.e., it is +grad f, in
   * world coordinates (per unit length, not per grid step). Differences are
   * taken along the grid indices and mapped through S^{-T}, so skewed grids
   * give the true gradient.
   * @param i x index
   * @param j y index
   * @param k z index
   * @return Gradient vector at the specified point.
   */
  std::array<float, 3> computeGradient(int i, int j, int k) const;

  /**
   * Get the values of the eight corners of a cube defined by the indices
   * (i, j, k).
   * @param i x index
   * @param j y index
   * @param k z index
   * @return Array of values at the eight corners.
   */
  std::array<float, 8> getValsCube(int i, int j, int k) const;

  /**
   * Get the gradients at the eight corners of the cube defined by the indices
   * (i, j, k).
   * @param i x index
   * @param j y index
   * @param k z index
   * @return Array of gradients at the eight corners. Each gradient is a 3D
   * vector.
   */
  std::array<std::array<float, 3>, 8> getGradCube(int i, int j, int k) const;

  /**
   * Get the data value at the specified indices. This is called for every
   * voxel, so it makes a single memory-safety check: an index that lies
   * outside the data gives zero. It does not check each axis, so an index
   * just past one axis may alias a point of the grid; use value() for
   * interpolation at the edges.
   * @param i x index
   * @param j y index
   * @param k z index
   * @return Value at the specified indices.
   */
  float getData(int i, int j, int k) const;

  int nx() const { return m_points.x(); }
  int ny() const { return m_points.y(); }
  int nz() const { return m_points.z(); }

  inline unsigned int linearIndex(int x, int y, int z) const;

  /**
   * Retrieves the positions of the eight corners of a cube at grid indices
   * (i, j, k).
   *
   * The indices (i, j, k) are converted to real-space positions (xpos, ypos,
   * zpos), mapping grid indices to physical coordinates. The method returns a
   * cell that spans one step along each of the i, j and k grid axes (a
   * parallelepiped for a skewed grid), with the step vectors given by
   * steps().
   *
   * @param i X-index.
   * @param j Y-index.
   * @param k Z-index.
   * @return A `std::array` of eight `(x, y, z)` coordinates representing the
   * cube's corners.
   */

  std::array<std::array<float, 3>, 8> getPosCube(int i, int j, int k) const;

protected:
  std::vector<float> m_data;
  Vector3 m_min, m_max, m_spacing;
  Vector3i m_points;
  float m_minValue, m_maxValue;
  std::string m_name;
  Type m_cubeType;
  Mutex* m_lock;
  /** Columns are the step vectors along i, j, k. */
  Matrix3 m_steps;
  /** The inverse of m_steps; only set (and used) for a skewed grid. */
  Matrix3 m_stepsInverse;
  /** True when m_steps has exactly zero off-diagonal elements. */
  bool m_axisAligned;

  /** Set every geometry member from an origin, dimensions and steps. */
  void applyLimits(const Vector3& origin, const Vector3i& dim,
                   const Matrix3& steps);
  /** Fractional grid index of a position, or false if not finite. */
  bool fractionalIndex(const Vector3& pos, Vector3& index) const;
  /** computeGradient() without the check that the data matches the grid. */
  std::array<float, 3> gradientAt(int i, int j, int k) const;
};

inline bool Cube::setValue(unsigned int i, float value_)
{
  if (i < m_data.size()) {
    m_data[i] = value_;
    if (value_ > m_maxValue)
      m_maxValue = value_;
    if (value_ < m_minValue)
      m_minValue = value_;
    return true;
  } else
    return false;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_CUBE_H
