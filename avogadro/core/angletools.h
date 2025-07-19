/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLETOOLS_H
#define AVOGADRO_CORE_ANGLETOOLS_H

#include <avogadro/core/vector.h>

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
 * Calculate the out-of-plane angle for a point in space.
 * @param point The point to calculate the angle for.
 * @param b The first point in the plane.
 * @param c The second point in the plane.
 * @param d The third point in the plane.
 * @return The out-of-plane angle in degrees.
 */
inline Real outOfPlaneAngle(const Vector3& point, const Vector3& b,
                            const Vector3& c, const Vector3& d)
{
  Real angle = 0.0;

  Vector3 bc = b - c;
  Vector3 cd = c - d;

  Vector3 normal = bc.cross(cd);
  Vector3 ac = point - c;
  // we can get the angle by taking the dot product of the normal
  // with the vector from the point to the center of the triangle
  Real theta = std::acos(ac.dot(normal) / (ac.norm() * normal.norm()));
  angle = 90.0 - (theta * RAD_TO_DEG_D);
  return angle;
}

} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLETOOLS_H
