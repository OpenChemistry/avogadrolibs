/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "neighborperceiver.h"

#include <algorithm>
#include <cmath>

namespace Avogadro::Core {

NeighborPerceiver::NeighborPerceiver(const Array<Vector3> points,
                                     float maxDistance)
  : m_maxDistance(maxDistance), m_binSize(maxDistance)
{
  if (!points.size())
    return;

  if (m_maxDistance <= 0 || !std::isfinite(m_maxDistance))
    return;

  // find the bounding box of the finite points; non-finite points (malformed
  // input) are never binned
  bool found = false;
  for (Index i = 0; i < points.size(); i++) {
    const Vector3& ipos = points[i];
    if (!ipos.allFinite())
      continue;
    if (!found) {
      m_minPos = ipos;
      m_maxPos = ipos;
      found = true;
      continue;
    }
    for (size_t c = 0; c < 3; c++) {
      m_minPos(c) = std::min(ipos(c), m_minPos(c));
      m_maxPos(c) = std::max(ipos(c), m_maxPos(c));
    }
  }
  if (!found)
    return;

  // Group points into cubic bins so that each point is only checked against
  // other points inside bins within a 3-dimensional Moore neighborhood.
  //
  // The bin edge is always maxDistance, so that neighborhood holds every point
  // within maxDistance of the query. Only occupied bins are stored, so widely
  // spread points (a single stray atom far from a molecule) cost nothing.
  //
  // Bins are anchored at the bounding box minimum, which keeps the bins of
  // ordinary molecules stable. If the extent spans so many bins that
  // (p - min) would lose the precision to tell nearby points apart, anchor at
  // the origin instead, where the spacing of doubles is finest.
  constexpr double maxAnchoredBins = 1099511627776.0; // 2^40
  m_anchor = m_minPos;
  for (size_t c = 0; c < 3; c++) {
    const double extent = m_maxPos(c) - m_minPos(c);
    if (!std::isfinite(extent) || extent / m_binSize > maxAnchoredBins) {
      m_anchor = Vector3::Zero();
      break;
    }
  }

  m_bins.reserve(points.size());
  for (Index i = 0; i < points.size(); i++) {
    BinKey key;
    if (getBinIndex(points[i], key))
      m_bins[key].push_back(i);
  }
}

void NeighborPerceiver::getNeighborsInclusiveInPlace(Array<Index>& out,
                                                     const Vector3& point) const
{
  out.clear();
  if (m_bins.empty())
    return;

  BinKey center;
  if (!getBinIndex(point, center))
    return;

  BinKey key;
  for (int64_t dx = -1; dx <= 1; dx++) {
    key[0] = center[0] + dx;
    for (int64_t dy = -1; dy <= 1; dy++) {
      key[1] = center[1] + dy;
      for (int64_t dz = -1; dz <= 1; dz++) {
        key[2] = center[2] + dz;
        const auto it = m_bins.find(key);
        if (it != m_bins.end())
          out.insert(out.end(), it->second.begin(), it->second.end());
      }
    }
  }
}

Array<Index> NeighborPerceiver::getNeighborsInclusive(
  const Vector3& point) const
{
  Array<Index> r;
  getNeighborsInclusiveInPlace(r, point);
  return r;
}

bool NeighborPerceiver::getBinIndex(const Vector3& point, BinKey& key) const
{
  if (!point.allFinite())
    return false;

  // Clamping in double before the cast keeps huge coordinates well defined and
  // leaves room for cell +/- 1. Clamping is 1-Lipschitz, so two points within
  // maxDistance still land in bins at most one apart.
  constexpr double limit = 1.0e15;
  for (size_t c = 0; c < 3; c++) {
    const double v = std::floor((point(c) - m_anchor(c)) / m_binSize);
    if (std::isnan(v))
      return false;
    key[c] = static_cast<int64_t>(std::clamp(v, -limit, limit));
  }
  return true;
}

} // namespace Avogadro::Core
