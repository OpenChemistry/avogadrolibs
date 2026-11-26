/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GEOMETRYBOUNDS_P_H
#define AVOGADRO_RENDERING_GEOMETRYBOUNDS_P_H

#include <avogadro/core/vector.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace Avogadro::Rendering {

/**
 * An axis-aligned box around a drawable's primitives, used to reject a pick
 * ray before scanning them. Not installed: private to the library and tests.
 */
struct GeometryBounds
{
  Vector3f min = Vector3f::Zero();
  Vector3f max = Vector3f::Zero();
  // False for an empty drawable or one with non-finite data: the box then
  // says nothing and the caller scans everything.
  bool usable = false;

  /** Grow the box to hold a ball of @p radius around @p center. */
  void include(const Vector3f& center, float radius)
  {
    const float r = std::abs(radius);
    if (!center.allFinite() || !std::isfinite(r)) {
      m_finite = false;
      return;
    }
    const Vector3f lo = center - Vector3f::Constant(r);
    const Vector3f hi = center + Vector3f::Constant(r);
    if (!m_any) {
      min = lo;
      max = hi;
      m_any = true;
    } else {
      min = min.cwiseMin(lo);
      max = max.cwiseMax(hi);
    }
  }

  /** Call once after the last include(): pads the box and sets usable. */
  void finish()
  {
    usable = m_any && m_finite;
    if (!usable)
      return;
    // Pad by far more than the float error of the exact tests, so a ray
    // those tests accept can never be rejected here.
    const float scale =
      std::max(min.cwiseAbs().maxCoeff(), max.cwiseAbs().maxCoeff());
    const float pad = 1.0e-4f * (1.0f + scale);
    min -= Vector3f::Constant(pad);
    max += Vector3f::Constant(pad);
  }

private:
  bool m_any = false;
  bool m_finite = true;
};

/**
 * Whether the half-line from @p origin along @p direction can touch the box.
 * Conservative: true whenever the answer is in doubt (a non-finite or
 * non-unit direction, which the exact tests treat in their own way).
 */
inline bool rayMayHitBounds(const GeometryBounds& bounds,
                            const Vector3f& origin, const Vector3f& direction)
{
  if (!bounds.usable || !origin.allFinite() || !direction.allFinite())
    return true;
  const float length2 = direction.squaredNorm();
  if (!(length2 > 0.99f && length2 < 1.01f))
    return true;

  float tNear = 0.0f; // the ray starts at the origin
  float tFar = std::numeric_limits<float>::max();
  for (int axis = 0; axis < 3; ++axis) {
    const float d = direction[axis];
    const float o = origin[axis];
    if (std::abs(d) < 1.0e-20f) {
      // Parallel to this pair of faces: inside the slab or never.
      if (o < bounds.min[axis] || o > bounds.max[axis])
        return false;
      continue;
    }
    const float inv = 1.0f / d;
    float t1 = (bounds.min[axis] - o) * inv;
    float t2 = (bounds.max[axis] - o) * inv;
    if (t1 > t2)
      std::swap(t1, t2);
    tNear = std::max(tNear, t1);
    tFar = std::min(tFar, t2);
    if (tNear > tFar)
      return false;
  }
  return true;
}

/**
 * A lazily computed GeometryBounds that cannot go stale unnoticed.
 *
 * The geometry classes hand out their arrays by mutable reference, so the
 * cache cannot see every edit. The contract is the one the GPU upload
 * already has: whoever edits in place calls markDirty(). While the geometry
 * is dirty the cache gives no box (and forgets any it held); it is computed
 * only for clean geometry, and the geometry calls invalidate() when it
 * clears the dirty flag or changes its contents itself.
 */
class CachedBounds
{
public:
  void invalidate() { m_valid = false; }

  /**
   * @param geometryDirty The geometry's dirty flag.
   * @param compute Callable returning a finished GeometryBounds.
   * @return The box to test against, or nullptr for "scan everything".
   */
  template <class Compute>
  const GeometryBounds* acquire(bool geometryDirty, Compute&& compute)
  {
    if (geometryDirty) {
      m_valid = false;
      return nullptr;
    }
    if (!m_valid) {
      m_bounds = compute();
      m_valid = true;
    }
    return m_bounds.usable ? &m_bounds : nullptr;
  }

  /** Whether a box is currently held (for tests). */
  bool valid() const { return m_valid; }

private:
  GeometryBounds m_bounds;
  bool m_valid = false;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_GEOMETRYBOUNDS_P_H
