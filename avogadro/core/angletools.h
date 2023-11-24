/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLETOOLS_H
#define AVOGADRO_CORE_ANGLETOOLS_H

#include <avogadro/core/vector.h>

#include <cmath>

namespace Avogadro {

inline Real bondAngle(const Vector3& b0, const Vector3& b1)
{
  // standard formula, e.g.
  // https://scicomp.stackexchange.com/q/27689/14517
  // Since we're using bonds, v. small angles are okay
  // only problem is if bond lengths are v. v. small
  //   but that's unlikely in practice
  const Real dot = -1.0 * b0.dot(b1);
  const Real norms = b0.norm() * b1.norm();
  return std::acos(dot / norms) * RAD_TO_DEG_D;
}

inline Real dihedralAngle(const Vector3& b0, const Vector3& b1,
                          const Vector3& b2)
{
  // See Praxeolitic https://stackoverflow.com/a/34245697/131896
  const Vector3 n0 = -1.0 * b0;
  const Vector3 b1n = b1.normalized();

  // v = projection of b0 onto plane perpendicular to b1
  //   = n0 minus component that aligns with b1
  // w = projection of b2 onto plane perpendicular to b1
  //   = b2 minus component that aligns with b1
  const Vector3 v = n0 - n0.dot(b1n) * b1n;
  const Vector3 w = b2 - b2.dot(b1n) * b1n;

  // angle between v and w in a plane is the torsion angle
  // v and w may not be normalized but that's fine since tan is y/x
  const Real x(v.dot(w));
  const Real y(b1n.cross(v).dot(w));
  return std::atan2(y, x) * RAD_TO_DEG_D;
}

inline Real calcAngle(const Vector3& v1, const Vector3& v2, const Vector3& v3)
{
  Vector3 v12 = v1 - v2;
  Vector3 v23 = v2 - v3;
  return bondAngle(v12, v23);
}

inline Real calcDihedral(const Vector3& v1, const Vector3& v2,
                         const Vector3& v3, const Vector3& v4)
{
  Vector3 v12 = v2 - v1;
  Vector3 v23 = v3 - v2;
  Vector3 v34 = v4 - v3;
  return dihedralAngle(v12, v23, v34);
}

} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLETOOLS_H
