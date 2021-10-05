/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLETOOLS_H
#define AVOGADRO_CORE_ANGLETOOLS_H

#include <avogadro/core/vector.h>

#include <cmath>

namespace Avogadro {

inline Real bondAngle(const Vector3& b0, const Vector3& b1) {
  // standard formula, e.g.
  // https://scicomp.stackexchange.com/q/27689/14517
  // Since we're using bonds, v. small angles are okay
  // only problem is if bond lengths are v. v. small
  //   but that's unlikely in practice
  const Real dot = -1.0*b0.dot(b1);
  const Real norms = b0.norm() * b1.norm();
  return std::acos(dot / norms) * RAD_TO_DEG_D;
}

inline Real dihedralAngle(const Vector3& b0, const Vector3& b1, const Vector3& b2)
{
  // See wikipedia
  const Vector3 n0 = -1.0*b0;
  const Vector3 b0xb1 = n0.cross(b1);
  const Vector3 b1xb2 = b2.cross(b1);
  const Vector3 b0xb1_x_b1xb2 = b0xb1.cross(b1xb2);

  const Real x(b0xb1.dot(b1xb2));
  const Real y( (b0xb1_x_b1xb2.dot(b1)) * 1.0 / (b1.norm()));
  return std::atan2(y, x) * RAD_TO_DEG_D;
}

inline Real calcAngle(const Vector3 &v1, const Vector3 &v2, const Vector3 &v3) {
  Vector3 v12 = v1 - v2;
  Vector3 v23 = v2 - v3;
  return bondAngle(v12, v23);
}

inline Real calcDihedral(const Vector3 &v1, const Vector3 &v2, const Vector3 &v3, const Vector3 &v4) {
  Vector3 v12 = v2 - v1;
  Vector3 v23 = v3 - v2;
  Vector3 v34 = v4 - v3;
  return dihedralAngle(v12, v23, v34);
}

} // end Avogadro namespace

#endif // AVOGADRO_CORE_ANGLETOOLS_H
