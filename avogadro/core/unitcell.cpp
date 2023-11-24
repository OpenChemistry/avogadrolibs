/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "unitcell.h"

#include <cmath>

namespace Avogadro::Core {

void UnitCell::setCellParameters(Real a_, Real b_, Real c_, Real al, Real be,
                                 Real ga)
{
  // Convert parameters to matrix. See "Appendix 2: Coordinate Systems and
  // Transformations" of the PDB guide (ref v2.2, 4/23/13,
  // http://www.bmsc.washington.edu/CrystaLinks/man/pdb/guide2.2_frame.html)
  const Real cosAlpha = std::cos(al);
  const Real cosBeta = std::cos(be);
  const Real cosGamma = std::cos(ga);
  const Real sinGamma = std::sin(ga);

  m_cellMatrix(0, 0) = a_;
  m_cellMatrix(1, 0) = static_cast<Real>(0.0);
  m_cellMatrix(2, 0) = static_cast<Real>(0.0);

  m_cellMatrix(0, 1) = b_ * cosGamma;
  m_cellMatrix(1, 1) = b_ * sinGamma;
  m_cellMatrix(2, 1) = static_cast<Real>(0.0);

  m_cellMatrix(0, 2) = c_ * cosBeta;
  m_cellMatrix(1, 2) = c_ * (cosAlpha - cosBeta * cosGamma) / sinGamma;
  m_cellMatrix(2, 2) =
    (c_ / sinGamma) *
    std::sqrt(
      static_cast<Real>(1.0) -
      ((cosAlpha * cosAlpha) + (cosBeta * cosBeta) + (cosGamma * cosGamma)) +
      (static_cast<Real>(2.0) * cosAlpha * cosBeta * cosGamma));
  computeFractionalMatrix();
}

Real UnitCell::signedAngleRadians(const Vector3& v1, const Vector3& v2,
                                  const Vector3& axis)
{
  const Vector3 crossProduct(v1.cross(v2));
  const Real crossProductNorm(crossProduct.norm());
  const Real dotProduct(v1.dot(v2));
  const Real signDet(crossProduct.dot(axis));
  const Real angle(std::atan2(crossProductNorm, dotProduct));
  return signDet > 0.f ? angle : -angle;
}

} // end namespace Avogadro
