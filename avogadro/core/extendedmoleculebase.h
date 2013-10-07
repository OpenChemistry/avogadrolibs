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

#ifndef AVOGADRO_CORE_EXTENDEDMOLECULEBASE_H
#define AVOGADRO_CORE_EXTENDEDMOLECULEBASE_H

#include "avogadrocore.h"

#include "matrix.h"
#include "vector.h"

#include <cmath>

namespace Avogadro {
namespace Core {

template <class MoleculeBase>
class ExtendedMoleculeBase : public MoleculeBase
{
public:
  typedef MoleculeBase MoleculeType;

  ExtendedMoleculeBase();
  ~ExtendedMoleculeBase() AVO_OVERRIDE;

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

template <class MoleculeBase>
ExtendedMoleculeBase<MoleculeBase>::ExtendedMoleculeBase()
  : m_cellMatrix(Matrix3::Identity())
{
}

template <class MoleculeBase>
ExtendedMoleculeBase<MoleculeBase>::~ExtendedMoleculeBase()
{
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::setAVector(const Vector3 &v)
{
  m_cellMatrix.row(0) = v.transpose();
  computeFractionalMatrix();
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::setBVector(const Vector3 &v)
{
  m_cellMatrix.row(1) = v.transpose();
  computeFractionalMatrix();
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::setCVector(const Vector3 &v)
{
  m_cellMatrix.row(2) = v.transpose();
  computeFractionalMatrix();
}

template <class MoleculeBase>
Real ExtendedMoleculeBase<MoleculeBase>::alpha() const
{
  return signedAngleRadians(bVector(), cVector(), aVector());
}

template <class MoleculeBase>
Real ExtendedMoleculeBase<MoleculeBase>::beta() const
{
  return signedAngleRadians(cVector(), aVector(), bVector());
}

template <class MoleculeBase>
Real ExtendedMoleculeBase<MoleculeBase>::gamma() const
{
  return signedAngleRadians(aVector(), bVector(), cVector());
}

template <class MoleculeBase>
Real ExtendedMoleculeBase<MoleculeBase>::volume() const
{
  return std::fabs(aVector().cross(bVector()).dot(cVector()));
}

template <class MoleculeBase>
Vector3 ExtendedMoleculeBase<MoleculeBase>::
imageOffset(int i, int j, int k) const
{
  return (  static_cast<Real>(i) * m_cellMatrix.row(0)
          + static_cast<Real>(j) * m_cellMatrix.row(1)
          + static_cast<Real>(k) * m_cellMatrix.row(2)).transpose();
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::
setCellParameters(Real a_, Real b_, Real c_, Real al, Real be, Real ga)
{
  // Taken from the pdb specification for converting params to matrix.
  const Real cosAlpha = std::cos(al);
  const Real cosBeta  = std::cos(be);
  const Real cosGamma = std::cos(ga);
  const Real sinGamma = std::sin(ga);

  m_cellMatrix(0, 0) = a_;
  m_cellMatrix(0, 1) = static_cast<Real>(0.0);
  m_cellMatrix(0, 2) = static_cast<Real>(0.0);

  m_cellMatrix(1, 0) = b_ * cosGamma;
  m_cellMatrix(1, 1) = b_ * sinGamma;
  m_cellMatrix(1, 2) = static_cast<Real>(0.0);

  m_cellMatrix(2, 0) = c_ * cosBeta;
  m_cellMatrix(2, 1) = c_ * (cosAlpha - cosBeta * cosGamma) / sinGamma;
  m_cellMatrix(2, 2) = (c_ / sinGamma) * std::sqrt(
        static_cast<Real>(1.0)
        - ((cosAlpha * cosAlpha) + (cosBeta * cosBeta) + (cosGamma * cosGamma))
        + (static_cast<Real>(2.0) * cosAlpha * cosBeta * cosGamma));
  computeFractionalMatrix();
}

template <class MoleculeBase>
const Matrix3 &ExtendedMoleculeBase<MoleculeBase>::cellMatrix() const
{
  return m_cellMatrix;
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::setCellMatrix(const Matrix3 &m)
{
  m_cellMatrix = m;
  computeFractionalMatrix();
}

template <class MoleculeBase>
const Matrix3 &ExtendedMoleculeBase<MoleculeBase>::fractionalMatrix() const
{
  return m_fractionalMatrix;
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::setFractionalMatrix(const Matrix3 &m)
{
  m_fractionalMatrix = m;
  computeCellMatrix();
}

template <class MoleculeBase>
Vector3 ExtendedMoleculeBase<MoleculeBase>::
toFractional(const Vector3 &cart) const
{
  return m_fractionalMatrix * cart;
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::
toFractional(const Vector3 &cart, Vector3 &frac) const
{
  frac = m_fractionalMatrix * cart;
}

template <class MoleculeBase>
Vector3 ExtendedMoleculeBase<MoleculeBase>::toCartesian(const Vector3 &f) const
{
  return m_cellMatrix * f;
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::
toCartesian(const Vector3 &frac, Vector3 &cart) const
{
  cart = m_cellMatrix * frac;
}

template <class MoleculeBase>
Vector3 ExtendedMoleculeBase<MoleculeBase>::
wrapFractional(const Vector3 &f) const
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

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::
wrapFractional(const Vector3 &f, Vector3 &wrapped) const
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
  return wrapped;
}

template <class MoleculeBase>
Vector3 ExtendedMoleculeBase<MoleculeBase>::
wrapCartesian(const Vector3 &cart) const
{
  Vector3 result = toFractional(cart);
  wrapFractional(result, result);
  toCartesian(result, result);
  return result;
}

template <class MoleculeBase>
void ExtendedMoleculeBase<MoleculeBase>::
wrapCartesian(const Vector3 &cart, Vector3 &wrapped) const
{
  toFractional(cart, wrapped);
  wrapFractional(wrapped, wrapped);
  toCartesian(wrapped, wrapped);
}

template <class MoleculeBase>
Real ExtendedMoleculeBase<MoleculeBase>::
signedAngleRadians(const Vector3 &v1, const Vector3 &v2, const Vector3 &axis)
{
  const Vector3 crossProduct(v1.cross(v2));
  const Real crossProductNorm(crossProduct.norm());
  const Real dotProduct(v1.dot(v2));
  const Real signDet(crossProduct.dot(axis));
  const Real angle(std::atan2(crossProductNorm, dotProduct));
  return signDet > 0.f ? angle : -angle;
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_EXTENDEDMOLECULEBASE_H
