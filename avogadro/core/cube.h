/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CUBE_H
#define AVOGADRO_CORE_CUBE_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "vector.h"

#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;
class Mutex;

/**
 * @class Cube cube.h <avogadro/core/cube.h>
 * @brief Provide a data structure for regularly spaced 3D grids.
 * @author Marcus D. Hanwell
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
   * @return The minimum point in the cube.
   */
  Vector3 min() const { return m_min; }

  /**
   * @return The maximum point in the cube.
   */
  Vector3 max() const { return m_max; }

  /**
   * @return The spacing of the grid.
   */
  Vector3 spacing() const { return m_spacing; }

  /**
   * @return The x, y and z dimensions of the cube.
   */
  Vector3i dimensions() const { return m_points; }

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param max The maximum point in the cube.
   * @param points The number of (integer) points in the cube.
   */
  bool setLimits(const Vector3& min, const Vector3& max,
                 const Vector3i& points);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param max The maximum point in the cube.
   * @param spacing The interval between points in the cube.
   */
  bool setLimits(const Vector3& min, const Vector3& max, float spacing);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param dim The integer dimensions of the cube in x, y and z.
   * @param spacing The interval between points in the cube.
   */
  bool setLimits(const Vector3& min, const Vector3i& dim, float spacing);

  /**
   * Set the limits of the cube.
   * @param min The minimum point in the cube.
   * @param dim The integer dimensions of the cube in x, y and z.
   * @param spacing The interval between points in the cube.
   */
  bool setLimits(const Vector3& min, const Vector3i& dim,
                 const Vector3& spacing);

  /**
   * Set the limits of the cube - copy the limits of an existing Cube.
   * @param cube Existing Cube to copy the limits from.
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
   * @return Vector containing all the data in a one-dimensional array.
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
  bool fillStripe(
    unsigned int i, unsigned int j, unsigned int kfirst, unsigned int klast, float value
  );

  /**
   * @return The minimum  value at any point in the Cube.
   */
  float minValue() const { return m_minValue; }

  /**
   * @return The maximum  value at any point in the Cube.
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

protected:
  std::vector<float> m_data;
  Vector3 m_min, m_max, m_spacing;
  Vector3i m_points;
  float m_minValue, m_maxValue;
  std::string m_name;
  Type m_cubeType;
  Mutex* m_lock;
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

} // End Core namespace
} // End Avogadro namespace

#endif // AVOGADRO_CORE_CUBE_H
