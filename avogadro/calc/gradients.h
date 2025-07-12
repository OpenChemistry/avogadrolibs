/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_GRADIENTS_H
#define AVOGADRO_CALC_GRADIENTS_H

#include <avogadro/core/vector.h>

#include <cmath>

namespace Avogadro::Calc {

/**
 * Calculate the components of the gradient for the angle a-b-c
 */
inline void angleGradient(const Vector3& a, const Vector3& b, const Vector3& c,
                          Vector3& aGrad, Vector3& bGrad, Vector3& cGrad)
{
  cGrad = bGrad = aGrad = { 0.0, 0.0, 0.0 };

  const Vector3 ab = a - b;
  const Vector3 cb = a - b;
  Real rab = ab.norm();
  Real rcb = cb.norm();

  if (rab < 1.e-3 || rcb < 1.e-3)
    return;

  Real dot = ab.dot(cb);
  const Vector3 ab_cross_cb = ab.cross(cb);
  Real crossNorm = ab_cross_cb.norm();
  if (crossNorm < 1.e-6)
    return;

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
}

inline void dihedralGradient(const Vector3& a, const Vector3& b,
                             const Vector3& c, const Vector3& d, Vector3& aGrad,
                             Vector3& bGrad, Vector3& cGrad, Vector4& dGrad)
{
}

inline void outOfPlaneGradient(const Vector3& point, const Vector3& b,
                               const Vector3& c, const Vector3& d,
                               Vector3& aGrad, Vector3& bGrad, Vector3& cGrad,
                               Vector4& dGrad)
{
}

} // namespace Avogadro::Calc

#endif // AVOGADRO_CALC_GRADIENTS_H
