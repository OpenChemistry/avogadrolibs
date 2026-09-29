/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "neighborperceiver.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace Avogadro::Core {

NeighborPerceiver::NeighborPerceiver(const Array<Vector3> points,
                                     float maxDistance)
  : m_maxDistance(maxDistance), m_binSize(maxDistance), m_binCount({ 0, 0, 0 }),
    m_cachedArray(nullptr)
{
  if (!points.size())
    return;

  if (m_maxDistance <= 0 || !std::isfinite(m_maxDistance))
    return;

  // find bounding box
  m_minPos = points[0];
  m_maxPos = points[0];
  for (Index i = 1; i < points.size(); i++) {
    Vector3 ipos = points[i];
    for (size_t c = 0; c < 3; c++) {
      m_minPos(c) = std::min(ipos(c), m_minPos(c));
      m_maxPos(c) = std::max(ipos(c), m_maxPos(c));
    }
  }

  // Validate bounding box (NaN/Inf from malformed input)
  for (size_t c = 0; c < 3; c++) {
    if (!std::isfinite(m_minPos(c)) || !std::isfinite(m_maxPos(c)))
      return;
  }

  // group points into cubic bins so that each point is only checked against
  // other points inside bins within a 3-dimensional Moore neighborhood.
  //
  // The bin edge starts at maxDistance, which is what every ordinary input
  // uses (so binning is identical to a plain maxDistance grid). A very large
  // point set would need more bins than we are willing to allocate, so in that
  // case the edge is grown until it fits. Since the edge never drops below
  // maxDistance, the 27-bin neighborhood still holds every point within
  // maxDistance of the query; only the inclusive superset gets larger.
  //
  // The bin budget scales with the number of points: a grid with far more
  // bins than points is almost all empty vectors (24 bytes each). One million
  // bins (~24 MB, 100 per axis -- a 200 A cube at a 2 A cutoff) is the floor,
  // so every ordinary molecule is binned exactly as before; only huge, sparse
  // point sets get larger bins.
  constexpr double maxAxisBins = 1000;
  const double maxTotalBins = std::clamp(
    64.0 * static_cast<double>(points.size()), 1'000'000.0, 10'000'000.0);
  const double padding = 0.1;
  std::array<double, 3> extent;
  for (size_t c = 0; c < 3; c++) {
    extent[c] = m_maxPos(c) + padding - m_minPos(c);
    if (!std::isfinite(extent[c]))
      return;
  }

  m_binSize = m_maxDistance;
  bool fits = false;
  // Growing by 1.25 each pass reaches any finite extent long before this cap.
  for (int pass = 0; pass < 10000 && !fits; pass++) {
    double total = 1.0;
    fits = true;
    for (size_t c = 0; c < 3; c++) {
      double count = std::floor(extent[c] / m_binSize) + 1;
      if (!std::isfinite(count) || count < 1)
        count = 1;
      if (count > maxAxisBins)
        fits = false;
      total *= count;
      m_binCount[c] = static_cast<int>(std::min(count, maxAxisBins));
    }
    if (total > maxTotalBins)
      fits = false;
    if (!fits)
      m_binSize *= 1.25;
  }
  if (!fits) {
    m_binCount = { 0, 0, 0 };
    return;
  }

  std::vector<std::vector<std::vector<std::vector<Index>>>> bins(
    m_binCount[0], std::vector<std::vector<std::vector<Index>>>(
                     m_binCount[1], std::vector<std::vector<Index>>(
                                      m_binCount[2], std::vector<Index>())));
  m_bins = std::move(bins);
  for (Index i = 0; i < points.size(); i++) {
    std::array<int, 3> bin_index = getBinIndex(points[i]);
    if (bin_index[0] >= 0 && bin_index[0] < m_binCount[0] &&
        bin_index[1] >= 0 && bin_index[1] < m_binCount[1] &&
        bin_index[2] >= 0 && bin_index[2] < m_binCount[2]) {
      m_bins[bin_index[0]][bin_index[1]][bin_index[2]].push_back(i);
    }
  }
}

void NeighborPerceiver::getNeighborsInclusiveInPlace(Array<Index>& out,
                                                     const Vector3& point) const
{
  if (m_bins.empty()) {
    out.clear();
    return;
  }

  const std::array<int, 3> bin_index = getBinIndex(point);
  if (&out == m_cachedArray && bin_index == m_cachedIndex)
    return;

  m_cachedIndex = bin_index;
  out.clear();
  for (int xi = std::max(int(1), bin_index[0]) - 1;
       xi < std::min(m_binCount[0], bin_index[0] + 2); xi++) {
    for (int yi = std::max(int(1), bin_index[1]) - 1;
         yi < std::min(m_binCount[1], bin_index[1] + 2); yi++) {
      for (int zi = std::max(int(1), bin_index[2]) - 1;
           zi < std::min(m_binCount[2], bin_index[2] + 2); zi++) {
        const std::vector<Index>& bin = m_bins[xi][yi][zi];
        out.insert(out.end(), bin.begin(), bin.end());
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

std::array<int, 3> NeighborPerceiver::getBinIndex(const Vector3& point) const
{
  // Points inside the box land in [0, binCount). A point one bin outside gets
  // -1 or binCount, which the neighbor loops turn into the adjacent edge bin;
  // anything further away is clamped to -2 or binCount + 1, which visits no
  // bins at all (it cannot be within reach of any binned point). Clamping in
  // double before the cast keeps huge and NaN coordinates well defined.
  std::array<int, 3> r = {};
  for (size_t c = 0; c < 3; c++) {
    const double v = std::floor((point(c) - m_minPos(c)) / m_binSize);
    if (std::isnan(v))
      r[c] = -2;
    else
      r[c] = static_cast<int>(
        std::clamp(v, -2.0, static_cast<double>(m_binCount[c]) + 1.0));
  }
  return r;
}

} // namespace Avogadro::Core
