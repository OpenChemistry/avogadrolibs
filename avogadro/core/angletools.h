/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLETOOLS_H
#define AVOGADRO_CORE_ANGLETOOLS_H

#include <avogadro/core/vector.h>

#include <algorithm>
#include <cmath>

namespace Avogadro {

/**
 * Calculate the bond angle between two bond vectors.
 * @param b0 The first bond vector (a-b)
 * @param b1 The second bond vector (b-c)
 * @return The bond angle in degrees.
 */
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

/**
 * Calculate the dihedral angle between three bond vectors.
 * @param b0 The first bond vector (a-b)
 * @param b1 The second bond vector (b-c)
 * @param b2 The third bond vector (c-d)
 * @return The dihedral angle in degrees.
 */
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

/**
 * Calculate the angle between three points in space.
 * @param v1 The first point.
 * @param v2 The second point (vertex).
 * @param v3 The third point.
 * @return The angle in degrees.
 */
inline Real calculateAngle(const Vector3& v1, const Vector3& v2,
                           const Vector3& v3)
{
  Vector3 v12 = v1 - v2;
  Vector3 v23 = v2 - v3;
  return bondAngle(v12, v23);
}

/**
 * Calculate the dihedral angle between four points in space.
 * @param v1 The first point.
 * @param v2 The second point.
 * @param v3 The third point.
 * @param v4 The fourth point.
 * @return The dihedral angle in degrees.
 */
inline Real calculateDihedral(const Vector3& v1, const Vector3& v2,
                              const Vector3& v3, const Vector3& v4)
{
  Vector3 v12 = v2 - v1;
  Vector3 v23 = v3 - v2;
  Vector3 v34 = v4 - v3;
  return dihedralAngle(v12, v23, v34);
}

/**
 * Calculate the Wilson out-of-plane angle for a central atom.
 * Uses the Wilson angle definition:
 *   sin(chi) = (u1 x u2) . u3 / |u1 x u2|
 * where u1, u2, u3 are unit vectors from the central atom to b, c, d.
 * @param point The central atom.
 * @param b The first surrounding atom.
 * @param c The second surrounding atom.
 * @param d The third surrounding atom (out-of-plane atom).
 * @return The out-of-plane angle in degrees.
 */
inline Real outOfPlaneAngle(const Vector3& point, const Vector3& b,
                            const Vector3& c, const Vector3& d)
{
  Vector3 u1 = b - point;
  Vector3 u2 = c - point;
  Vector3 u3 = d - point;

  const Real r1 = u1.norm();
  const Real r2 = u2.norm();
  const Real r3 = u3.norm();
  if (r1 < 1e-10 || r2 < 1e-10 || r3 < 1e-10)
    return 0.0;

  u1 /= r1;
  u2 /= r2;
  u3 /= r3;

  const Vector3 n = u1.cross(u2);
  const Real sinTheta = n.norm();
  if (sinTheta < 1e-10)
    return 0.0;

  Real sinChi = std::clamp(n.dot(u3) / sinTheta, -1.0, 1.0);
  return std::asin(sinChi) * RAD_TO_DEG_D;
}

} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLETOOLS_H
