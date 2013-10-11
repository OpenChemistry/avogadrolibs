/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_UNITCELL_H
#define AVOGADRO_CORE_UNITCELL_H

#include "avogadrocore.h"
#include "avogadrocoreexport.h"

#include "matrix.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT UnitCell
{
public:
  UnitCell();
  UnitCell(const UnitCell &other);
  ~UnitCell();
  UnitCell &operator=(UnitCell other);
  friend void swap(UnitCell &lhs, UnitCell &rhs);

  Vector3 aVector() const { return m_cellMatrix.row(0).transpose(); }
  Vector3 bVector() const { return m_cellMatrix.row(1).transpose(); }
  Vector3 cVector() const { return m_cellMatrix.row(2).transpose(); }
  void setAVector(const Vector3 &v);
  void setBVector(const Vector3 &v);
  void setCVector(const Vector3 &v);

  Real a() const { return m_cellMatrix.row(0).norm(); }
  Real b() const { return m_cellMatrix.row(1).norm(); }
  Real c() const { return m_cellMatrix.row(2).norm(); }
  Real alpha() const;
  Real beta()  const;
  Real gamma() const;

  void setCellParameters(Real a, Real b, Real c,
                         Real alpha, Real beta, Real gamma);

  Real volume() const;

  Vector3 imageOffset(int i, int j, int k) const;

  const Matrix3 &cellMatrix() const;
  void setCellMatrix(const Matrix3 &m);

  const Matrix3 &fractionalMatrix() const;
  void setFractionalMatrix(const Matrix3 &m);

  Vector3 toFractional(const Vector3 &cart) const;
  void toFractional(const Vector3 &cart, Vector3 &frac) const;

  Vector3 toCartesian(const Vector3 &frac) const;
  void toCartesian(const Vector3 &frac, Vector3 &cart) const;

  Vector3 wrapFractional(const Vector3 &frac) const;
  void wrapFractional(const Vector3 &frac, Vector3 &wrapped) const;

  Vector3 wrapCartesian(const Vector3 &cart) const;
  void wrapCartesian(const Vector3 &cart, Vector3 &wrapped) const;

private:
  static Real signedAngleRadians(const Vector3 &v1, const Vector3 &v2,
                                 const Vector3 &axis);
  void computeCellMatrix() { m_cellMatrix = m_fractionalMatrix.inverse(); }
  void computeFractionalMatrix() {m_fractionalMatrix = m_cellMatrix.inverse(); }


  Matrix3 m_cellMatrix;
  Matrix3 m_fractionalMatrix;
};

inline UnitCell::UnitCell()
  : m_cellMatrix(Matrix3::Identity())
{
}

inline UnitCell::UnitCell(const UnitCell &other)
  : m_cellMatrix(other.m_cellMatrix),
    m_fractionalMatrix(other.m_fractionalMatrix)
{
}

inline UnitCell::~UnitCell()
{
}

inline UnitCell &UnitCell::operator=(UnitCell other)
{
  using std::swap;
  swap(*this, other);
  return *this;
}

inline void swap(UnitCell &lhs, UnitCell &rhs)
{
  using std::swap;
  swap(lhs.m_cellMatrix, rhs.m_cellMatrix);
  swap(lhs.m_fractionalMatrix, rhs.m_fractionalMatrix);
}

inline void UnitCell::setAVector(const Vector3 &v)
{
  m_cellMatrix.row(0) = v.transpose();
  computeFractionalMatrix();
}

inline void UnitCell::setBVector(const Vector3 &v)
{
  m_cellMatrix.row(1) = v.transpose();
  computeFractionalMatrix();
}

inline void UnitCell::setCVector(const Vector3 &v)
{
  m_cellMatrix.row(2) = v.transpose();
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
  return (  static_cast<Real>(i) * m_cellMatrix.row(0)
          + static_cast<Real>(j) * m_cellMatrix.row(1)
          + static_cast<Real>(k) * m_cellMatrix.row(2)).transpose();
}

inline const Matrix3 &UnitCell::cellMatrix() const
{
  return m_cellMatrix;
}

inline void UnitCell::setCellMatrix(const Matrix3 &m)
{
  m_cellMatrix = m;
  computeFractionalMatrix();
}

inline const Matrix3 &UnitCell::fractionalMatrix() const
{
  return m_fractionalMatrix;
}

inline void UnitCell::setFractionalMatrix(const Matrix3 &m)
{
  m_fractionalMatrix = m;
  computeCellMatrix();
}

inline Vector3 UnitCell::toFractional(const Vector3 &cart) const
{
  return m_fractionalMatrix * cart;
}

inline void UnitCell::toFractional(const Vector3 &cart, Vector3 &frac) const
{
  frac = m_fractionalMatrix * cart;
}

inline Vector3 UnitCell::toCartesian(const Vector3 &f) const
{
  return m_cellMatrix * f;
}

inline void UnitCell::toCartesian(const Vector3 &frac, Vector3 &cart) const
{
  cart = m_cellMatrix * frac;
}

inline Vector3 UnitCell::wrapFractional(const Vector3 &f) const
{
  const Real one = static_cast<Real>(1.0);
  Vector3 result(
        std::fmod(f[0], one), std::fmod(f[1], one), std::fmod(f[2], one));
  if (result[0] < static_cast<Real>(0.0))
    ++result[0];
  if (result[1] < static_cast<Real>(0.0))
    ++result[1];
  if (result[2] < static_cast<Real>(0.0))
    ++result[2];
  return result;
}

inline void UnitCell::wrapFractional(const Vector3 &f, Vector3 &wrapped) const
{
  const Real one = static_cast<Real>(1.0);
  wrapped = Vector3(
        std::fmod(f[0], one), std::fmod(f[1], one), std::fmod(f[2], one));
  if (wrapped[0] < static_cast<Real>(0.0))
    ++wrapped[0];
  if (wrapped[1] < static_cast<Real>(0.0))
    ++wrapped[1];
  if (wrapped[2] < static_cast<Real>(0.0))
    ++wrapped[2];
}

inline Vector3 UnitCell::wrapCartesian(const Vector3 &cart) const
{
  Vector3 result = toFractional(cart);
  wrapFractional(result, result);
  toCartesian(result, result);
  return result;
}

inline void UnitCell::wrapCartesian(const Vector3 &cart, Vector3 &wrapped) const
{
  toFractional(cart, wrapped);
  wrapFractional(wrapped, wrapped);
  toCartesian(wrapped, wrapped);
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_UNITCELL_H
