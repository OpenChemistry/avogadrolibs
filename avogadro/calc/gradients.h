/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_GRADIENTS_H
#define AVOGADRO_CALC_GRADIENTS_H

#include <avogadro/core/vector.h>
#include <avogadro/core/angletools.h>

#include <algorithm>
#include <cmath>

namespace Avogadro::Calc {

/**
 * Calculate the components of the gradient for the distance a-b.
 * @return true if the length is well-defined.
 */
inline bool distanceGradient(const Vector3& a, const Vector3& b, Real& distance,
                             Vector3& aGrad, Vector3& bGrad)
{
  bGrad = aGrad = Vector3::Zero();

  const Vector3 ab = a - b;
  distance = ab.norm();
  if (distance < 1e-3)
    return false;

  const Vector3 direction = ab / distance;
  aGrad = direction;
  bGrad = -direction;
  return true;
}

/**
 * Calculate the components of the gradient for the angle a-b-c using atan2.
 * @return the angle between a-b-c in radians or 0.0 if ill-defined
 */
inline Real angleGradient(const Vector3& a, const Vector3& b, const Vector3& c,
                          Vector3& aGrad, Vector3& bGrad, Vector3& cGrad)
{
  cGrad = bGrad = aGrad = Vector3::Zero();

  const Vector3 ab = a - b;
  const Vector3 cb = c - b;
  const Real rab = ab.norm();
  const Real rcb = cb.norm();

  if (rab < 1.e-3 || rcb < 1.e-3)
    return 0.0;

  const Real dot = ab.dot(cb);
  const Vector3 ab_cross_cb = ab.cross(cb);
  const Real crossNorm = ab_cross_cb.norm();
  if (!std::isfinite(crossNorm) || crossNorm < 1.e-6)
    return 0.0;

  Real angle = atan2(crossNorm, dot);
  if (angle < -PI)
    angle += 2 * PI;
  else if (angle > PI)
    angle -= 2 * PI;

  // Use the cross product to get the gradients
  const Vector3 n = ab_cross_cb / crossNorm;

  // Gradients of the cross products
  Vector3 grad_cross_a = (cb.cross(n));
  Vector3 grad_cross_c = (n.cross(ab));
  Vector3 grad_cross_b = -(grad_cross_a + grad_cross_c);

  // Gradients of the dot product
  Vector3 grad_dot_a = cb;
  Vector3 grad_dot_c = ab;
  Vector3 grad_dot_b = -(cb + ab);

  // Final gradient using atan2 derivative: d/dx(atan2(y,x)) = (x*dy/dx -
  // y*dx/dx)/(x^2 + y^2)
  const Real denom = crossNorm * crossNorm + dot * dot;
  aGrad = (grad_cross_a * dot - crossNorm * grad_dot_a) / denom;
  bGrad = (grad_cross_b * dot - crossNorm * grad_dot_b) / denom;
  cGrad = (grad_cross_c * dot - crossNorm * grad_dot_c) / denom;

  return angle;
}

/**
 * Calculate the components of the gradient for the dihedral i-j-k-;
 * @return the torsion angle around i-j-k-l in radians
 */
inline Real dihedralGradient(const Vector3& i, const Vector3& j,
                             const Vector3& k, const Vector3& l, Vector3& iGrad,
                             Vector3& jGrad, Vector3& kGrad, Vector3& lGrad)
{
  lGrad = kGrad = jGrad = iGrad = Vector3::Zero();

  // get the bond vectors
  Vector3 ij = j - i;
  Vector3 jk = k - j;
  Vector3 kl = l - k;

  Real rij = ij.norm();
  Real rjk = jk.norm();
  Real rkl = kl.norm();

  Real phi = calculateDihedral(i, j, k, l) * DEG_TO_RAD;

  // check if the bond vectors are near zero
  if (rij < 1e-3 || rjk < 1e-3 || rkl < 1e-3)
    return phi; // skip this torsion

  Real sinPhi = sin(phi);
  Real cosPhi = cos(phi);

  // Using the BallView / Open Babel formula
  // https://doi.org/10.22028/D291-25896 (Appendix A)
  // Thanks to Andreas Moll
  // for the derivation of the gradients

  // get the unit vectors
  Vector3 n1 = ij / rij;
  Vector3 n2 = jk / rjk;
  Vector3 n3 = kl / rkl;

  // get the angles between ijk and jkl
  Vector3 n1_cross_n2 = n1.cross(n2);
  Vector3 n2_cross_n3 = n2.cross(n3);

  // check for near-zero cross products
  if (n1_cross_n2.norm() < 1e-6 || n2_cross_n3.norm() < 1e-6)
    return phi; // skip this torsion

  Real sinAngleIJK = n1_cross_n2.norm();
  Real sinAngleJKL = n2_cross_n3.norm();
  Real cosAngleIJK = n1.dot(n2);
  Real cosAngleJKL = n2.dot(n3);

  // get the gradient components
  iGrad = -n1_cross_n2 / (rij * sinAngleIJK * sinAngleIJK);
  lGrad = n2_cross_n3 / (rkl * sinAngleJKL * sinAngleJKL);

  // grad_j and grad_k are a bit more complicated
  // clamp the cosines to -1 to 1
  cosAngleIJK = std::clamp(cosAngleIJK, -1.0, 1.0);
  cosAngleJKL = std::clamp(cosAngleJKL, -1.0, 1.0);

  Real fraction1 = (rij / rjk) * (-cosAngleIJK);
  Real fraction2 = (rkl / rjk) * (-cosAngleJKL);
  jGrad = iGrad * (fraction1 - 1) - lGrad * (fraction2);
  kGrad = -(iGrad + lGrad + jGrad);

  return phi;
}

inline Real outOfPlaneGradient(const Vector3& point, const Vector3& b,
                               const Vector3& c, const Vector3& d,
                               Vector3& aGrad, Vector3& bGrad, Vector3& cGrad,
                               Vector3& dGrad)
{
  dGrad = cGrad = bGrad = aGrad = Vector3::Zero();

  // Bond vectors from central atom to surrounding atoms
  Vector3 u1 = b - point;
  Vector3 u2 = c - point;
  Vector3 u3 = d - point;

  const Real r1 = u1.norm();
  const Real r2 = u2.norm();
  const Real r3 = u3.norm();
  if (r1 < 1e-3 || r2 < 1e-3 || r3 < 1e-3)
    return 0.0;

  // Normalize to unit vectors
  u1 /= r1;
  u2 /= r2;
  u3 /= r3;

  // Use outOfPlaneAngle (Wilson angle) for the angle value
  const Real chi = outOfPlaneAngle(point, b, c, d) * DEG_TO_RAD;
  const Real sinChi = std::sin(chi);
  const Real cosChi = std::cos(chi);
  if (std::abs(cosChi) < 1e-6)
    return chi;

  // Cross product and derived quantities needed for gradient formulas
  const Vector3 n = u1.cross(u2);
  const Real sinTheta = n.norm();
  if (sinTheta < 1e-6)
    return chi;

  const Real cosTheta = u1.dot(u2);
  const Vector3 n_hat = n / sinTheta;
  const Real sinTheta2 = sinTheta * sinTheta;

  // Gradient for atom d (out-of-plane atom)
  dGrad = (n_hat - u3 * sinChi) / (r3 * cosChi);

  // Gradient for atom b (in-plane)
  const Vector3 u2xu3 = u2.cross(u3);
  bGrad = (u2xu3 * sinTheta - u1 * sinChi + u2 * sinChi * cosTheta) /
          (r1 * cosChi * sinTheta2);

  // Gradient for atom c (in-plane)
  const Vector3 u3xu1 = u3.cross(u1);
  cGrad = (u3xu1 * sinTheta - u2 * sinChi + u1 * sinChi * cosTheta) /
          (r2 * cosChi * sinTheta2);

  // Central atom gradient from translation invariance
  aGrad = -(bGrad + cGrad + dGrad);

  return chi;
}

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_GRADIENTS_H
