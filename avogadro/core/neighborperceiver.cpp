/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "neighborperceiver.h"

namespace Avogadro::Core {

NeighborPerceiver::NeighborPerceiver(const Array<Vector3> points, float maxDistance)
 : m_maxDistance(maxDistance), m_cachedArray(nullptr)
{
  if (!points.size()) return;

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

  // group points into cubic bins so that each point is only checked against
  // other points inside bins within a 3-dimensional Moore neighborhood
  for (size_t c = 0; c < 3; c++)
    m_binCount[c] = std::floor((m_maxPos(c) + 0.1 - m_minPos(c)) / m_maxDistance) + 1;
  std::vector<std::vector<std::vector<std::vector<Index>>>> bins(
    m_binCount[0], std::vector<std::vector<std::vector<Index>>>(
      m_binCount[1], std::vector<std::vector<Index>>(
        m_binCount[2], std::vector<Index>()
      )
    )
  );
  m_bins = bins;
  for (Index i = 0; i < points.size(); i++) {
    std::array<int, 3> bin_index = getBinIndex(points[i]);
    m_bins.at(bin_index[0]).at(bin_index[1]).at(bin_index[2]).push_back(i);
  }
}

void NeighborPerceiver::getNeighborsInclusiveInPlace(
    Array<Index> &out, const Vector3 &point
) const {
  const std::array<int, 3> bin_index = getBinIndex(point);
  if (&out == m_cachedArray && bin_index == m_cachedIndex)
    return;
  m_cachedArray = &out;
  m_cachedIndex = bin_index;
  out.clear();
  for (int xi = std::max(int(1), bin_index[0]) - 1;
      xi < std::min(m_binCount[0], bin_index[0] + 2); xi++) {
    for (int yi = std::max(int(1), bin_index[1]) - 1;
        yi < std::min(m_binCount[1], bin_index[1] + 2); yi++) {
      for (int zi = std::max(int(1), bin_index[2]) - 1;
          zi < std::min(m_binCount[2], bin_index[2] + 2); zi++) {
        const std::vector<Index> &bin = m_bins[xi][yi][zi];
        out.insert(out.end(), bin.begin(), bin.end());
      }
    }
  }
}

Array<Index> NeighborPerceiver::getNeighborsInclusive(const Vector3 &point) const
{
  Array<Index> r;
  getNeighborsInclusiveInPlace(r, point);
  return r;
}

std::array<int, 3> NeighborPerceiver::getBinIndex(const Vector3 &point) const
{
  std::array<int, 3> r;
  for (size_t c = 0; c < 3; c++) {
    r[c] = std::floor((point(c) - m_minPos(c)) / m_maxDistance);
  }
  return r; 
}

} // namespace Avogadro
