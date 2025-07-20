/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_GRADIENTS_H
#define AVOGADRO_CALC_GRADIENTS_H

#include <avogadro/core/vector.h>
#include <avogadro/core/angletools.h>

#include <cmath>

namespace Avogadro::Calc {

/**
 * Calculate the components of the gradient for the angle a-b-c
 * @return the angle between a-b-c in radians
 */
inline Real angleGradient(const Vector3& a, const Vector3& b, const Vector3& c,
                          Vector3& aGrad, Vector3& bGrad, Vector3& cGrad)
{
  cGrad = bGrad = aGrad = { 0.0, 0.0, 0.0 };

  const Vector3 ab = a - b;
  const Vector3 cb = c - b;
  const Real rab = ab.norm();
  const Real rcb = cb.norm();
  const Real dot = ab.dot(cb);
  const Real norms = rab * rcb;
  const Real angle = std::acos(-dot / norms);

  if (rab < 1.e-3 || rcb < 1.e-3)
    return angle;

  const Vector3 ab_cross_cb = ab.cross(cb);
  Real crossNorm = ab_cross_cb.norm();
  if (crossNorm < 1.e-6)
    return angle;

  // Use the cross product to get the gradients
  const Vector3 n = ab_cross_cb / crossNorm;

  // Gradients of the cross products
  Vector3 grad_cross_a = (cb.cross(n)).stableNormalized();
  Vector3 grad_cross_c = (n.cross(ab)).stableNormalized();
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
  lGrad = kGrad = jGrad = iGrad = { 0.0, 0.0, 0.0 };

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

  // skip this torsion
  if (std::abs(sinPhi) < 1e-6)
    return phi;

  // Using the BallView / Open Babel formula
  // http://dx.doi.org/10.22028/D291-25896 (Appendix A)
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
  dGrad = cGrad = bGrad = aGrad = { 0.0, 0.0, 0.0 };
  return 0.0;
}

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_GRADIENTS_H
