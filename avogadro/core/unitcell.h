/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_UNITCELL_H
#define AVOGADRO_CORE_UNITCELL_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "matrix.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

/**
 * @class UnitCell unitcell.h <avogadro/core/unitcell.h>
 * @brief The UnitCell class provides a representation of a crystal's unit cell.
 */
class AVOGADROCORE_EXPORT UnitCell
{
public:
  UnitCell();
  UnitCell(Real a, Real b, Real c, Real alpha, Real beta, Real gamma);
  UnitCell(const Vector3& a, const Vector3& b, const Vector3& c);
  explicit UnitCell(const Matrix3& cellMatrix);
  UnitCell(const UnitCell& other);
  ~UnitCell();
  UnitCell& operator=(UnitCell other);
  friend void swap(UnitCell& lhs, UnitCell& rhs);

  /** The lattice vector in the unit cell. Units: Angstrom @{ */
  Vector3 aVector() const { return m_cellMatrix.col(0); }
  Vector3 bVector() const { return m_cellMatrix.col(1); }
  Vector3 cVector() const { return m_cellMatrix.col(2); }
  void setAVector(const Vector3& v);
  void setBVector(const Vector3& v);
  void setCVector(const Vector3& v);
  /** @} */

  /** The length of the lattice vector in the unit cell. Units: Angstrom @{ */
  Real a() const { return m_cellMatrix.col(0).norm(); }
  Real b() const { return m_cellMatrix.col(1).norm(); }
  Real c() const { return m_cellMatrix.col(2).norm(); }
  /** @} */

  /** The angle (radians) between the 'b' and 'c' lattice vectors. */
  Real alpha() const;

  /** The angle (radians) between the 'c' and 'a' lattice vectors. */
  Real beta() const;

  /** The angle (radians) between the 'a' and 'b' lattice vectors. */
  Real gamma() const;

  /**
   * Set the cell parameters defining the unit cell. @a a, @a b, and @a c are
   * in Angstrom, @a alpha, @a beta, and @a gamma are in radians.
   */
  void setCellParameters(Real a, Real b, Real c, Real alpha, Real beta,
                         Real gamma);

  /**
   * The volume of the unit cell in cubic Angstroms.
   */
  Real volume() const;

  /**
   * @return A vector pointing to the origin of the translational image that is
   * @a i images in the a() direction, @a j images in the b() direction, and
   * @a k images in the c() direction.
   */
  Vector3 imageOffset(int i, int j, int k) const;

  /**
   * The cell matrix with lattice vectors as columns. Units: Angstrom @{
   */
  const Matrix3& cellMatrix() const;
  void setCellMatrix(const Matrix3& m);
  /** @} */

  /**
   * The matrix used to convert cartesian to fractional coordinates.
   */
  const Matrix3& fractionalMatrix() const;
  void setFractionalMatrix(const Matrix3& m);
  /** @} */

  /**
   * Convert the cartesian coordinate @a cart to fractional (lattice) units. @{
   */
  Vector3 toFractional(const Vector3& cart) const;
  void toFractional(const Vector3& cart, Vector3& frac) const;

  /**
   * Convert the fractional (lattice) coordinate @a frac to cartesian units. @{
   */
  Vector3 toCartesian(const Vector3& frac) const;
  void toCartesian(const Vector3& frac, Vector3& cart) const;
  /** @} */

  /**
   * Adjust the fractional (lattice) coordinate @a frac so that it lies within
   * the unit cell. @{
   */
  Vector3 wrapFractional(const Vector3& frac) const;
  void wrapFractional(const Vector3& frac, Vector3& wrapped) const;
  /** @} */

  /**
   * Adjust the cartesian coordinate @a cart so that it lies within the unit
   * cell. @{
   */
  Vector3 wrapCartesian(const Vector3& cart) const;
  void wrapCartesian(const Vector3& cart, Vector3& wrapped) const;
  /** @} */

  /**
   * Find the minimum fractional image of a fractional vector @a v.
   * A minimum image has all fractional coordinates between -0.5 and 0.5.
   */
  static Vector3 minimumImageFractional(const Vector3& v);

  /**
   * Find the minimum image of a Cartesian vector @a v.
   * A minimum image has all fractional coordinates between -0.5 and 0.5
   */
  Vector3 minimumImage(const Vector3& v) const;

  /**
   * Find the shortest distance between vectors @a v1 and @a v2.
   */
  Real distance(const Vector3& v1, const Vector3& v2) const;

private:
  static Real signedAngleRadians(const Vector3& v1, const Vector3& v2,
                                 const Vector3& axis);
  void computeCellMatrix() { m_cellMatrix = m_fractionalMatrix.inverse(); }
  void computeFractionalMatrix()
  {
    m_fractionalMatrix = m_cellMatrix.inverse();
  }

  Matrix3 m_cellMatrix;
  Matrix3 m_fractionalMatrix;
};

inline UnitCell::UnitCell()
  : m_cellMatrix(Matrix3::Identity()), m_fractionalMatrix(Matrix3::Identity())
{
}

inline UnitCell::UnitCell(Real a_, Real b_, Real c_, Real alpha_, Real beta_,
                          Real gamma_)
{
  setCellParameters(a_, b_, c_, alpha_, beta_, gamma_);
}

inline UnitCell::UnitCell(const Vector3& a_, const Vector3& b_,
                          const Vector3& c_)
{
  m_cellMatrix.col(0) = a_;
  m_cellMatrix.col(1) = b_;
  m_cellMatrix.col(2) = c_;
  computeFractionalMatrix();
}

inline UnitCell::UnitCell(const Matrix3& cellMatrix_)
{
  m_cellMatrix = cellMatrix_;
  computeFractionalMatrix();
}

inline UnitCell::UnitCell(const UnitCell& other)
  : m_cellMatrix(other.m_cellMatrix),
    m_fractionalMatrix(other.m_fractionalMatrix)
{
}

inline UnitCell::~UnitCell()
{
}

inline UnitCell& UnitCell::operator=(UnitCell other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(UnitCell& lhs, UnitCell& rhs)
{
  using std::swap;
  swap(lhs.m_cellMatrix, rhs.m_cellMatrix);
  swap(lhs.m_fractionalMatrix, rhs.m_fractionalMatrix);
}

inline void UnitCell::setAVector(const Vector3& v)
{
  m_cellMatrix.col(0) = v;
  computeFractionalMatrix();
}

inline void UnitCell::setBVector(const Vector3& v)
{
  m_cellMatrix.col(1) = v;
  computeFractionalMatrix();
}

inline void UnitCell::setCVector(const Vector3& v)
{
  m_cellMatrix.col(2) = v;
  computeFractionalMatrix();
}

inline Real UnitCell::alpha() const
{
  return signedAngleRadians(bVector(), cVector(), aVector());
}

inline Real UnitCell::beta() const
{
  return signedAngleRadians(cVector(), aVector(), bVector());
}

inline Real UnitCell::gamma() const
{
  return signedAngleRadians(aVector(), bVector(), cVector());
}

inline Real UnitCell::volume() const
{
  return std::fabs(aVector().cross(bVector()).dot(cVector()));
}

inline Vector3 UnitCell::imageOffset(int i, int j, int k) const
{
  return (static_cast<Real>(i) * m_cellMatrix.col(0) +
          static_cast<Real>(j) * m_cellMatrix.col(1) +
          static_cast<Real>(k) * m_cellMatrix.col(2));
}

inline const Matrix3& UnitCell::cellMatrix() const
{
  return m_cellMatrix;
}

inline void UnitCell::setCellMatrix(const Matrix3& m)
{
  m_cellMatrix = m;
  computeFractionalMatrix();
}

inline const Matrix3& UnitCell::fractionalMatrix() const
{
  return m_fractionalMatrix;
}

inline void UnitCell::setFractionalMatrix(const Matrix3& m)
{
  m_fractionalMatrix = m;
  computeCellMatrix();
}

inline Vector3 UnitCell::toFractional(const Vector3& cart) const
{
  return m_fractionalMatrix * cart;
}

inline void UnitCell::toFractional(const Vector3& cart, Vector3& frac) const
{
  frac = m_fractionalMatrix * cart;
}

inline Vector3 UnitCell::toCartesian(const Vector3& f) const
{
  return m_cellMatrix * f;
}

inline void UnitCell::toCartesian(const Vector3& frac, Vector3& cart) const
{
  cart = m_cellMatrix * frac;
}

inline Vector3 UnitCell::wrapFractional(const Vector3& f) const
{
  const Real one = static_cast<Real>(1.0);
  Vector3 result(std::fmod(f[0], one), std::fmod(f[1], one),
                 std::fmod(f[2], one));
  if (result[0] < static_cast<Real>(0.0))
    ++result[0];
  if (result[1] < static_cast<Real>(0.0))
    ++result[1];
  if (result[2] < static_cast<Real>(0.0))
    ++result[2];
  return result;
}

inline void UnitCell::wrapFractional(const Vector3& f, Vector3& wrapped) const
{
  const Real one = static_cast<Real>(1.0);
  wrapped =
    Vector3(std::fmod(f[0], one), std::fmod(f[1], one), std::fmod(f[2], one));
  if (wrapped[0] < static_cast<Real>(0.0))
    ++wrapped[0];
  if (wrapped[1] < static_cast<Real>(0.0))
    ++wrapped[1];
  if (wrapped[2] < static_cast<Real>(0.0))
    ++wrapped[2];
}

inline Vector3 UnitCell::wrapCartesian(const Vector3& cart) const
{
  Vector3 result = toFractional(cart);
  wrapFractional(result, result);
  toCartesian(result, result);
  return result;
}

inline void UnitCell::wrapCartesian(const Vector3& cart, Vector3& wrapped) const
{
  toFractional(cart, wrapped);
  wrapFractional(wrapped, wrapped);
  toCartesian(wrapped, wrapped);
}

inline Vector3 UnitCell::minimumImageFractional(const Vector3& v)
{
  Real x = v[0] - rint(v[0]);
  Real y = v[1] - rint(v[1]);
  Real z = v[2] - rint(v[2]);
  return Vector3(x, y, z);
}

inline Vector3 UnitCell::minimumImage(const Vector3& v) const
{
  return toCartesian(minimumImageFractional(toFractional(v)));
}

inline Real UnitCell::distance(const Vector3& v1, const Vector3& v2) const
{
  return minimumImage(v1 - v2).norm();
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_UNITCELL_H
