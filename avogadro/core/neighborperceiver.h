/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_NEIGHBORPERCEIVER_H
#define AVOGADRO_CORE_NEIGHBORPERCEIVER_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include "array.h"
#include "vector.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace Avogadro::Core {

/**
 * @class NeighborPerceiver neighborperceiver.h
 * <avogadro/core/neighborperceiver.h>
 * @brief This class can be used to find physically neighboring points in linear
 * average time.
 */
class AVOGADROCORE_EXPORT NeighborPerceiver
{
public:
  /**
   * Creates a NeighborPerceiver that detects neighbors up to at least some
   * distance.
   *
   * @param points Positions in 3D space to detect neighbors among.
   * @param maxDistance All neighbors strictly within this distance will be
   *                    detected. Should be as low as possible for best
   *                    performance.
   *
   * The bin size always equals maxDistance. Only occupied bins are stored, so
   * memory is proportional to the number of points however widely they are
   * spread. Points with non-finite coordinates are ignored: they are never
   * returned as neighbors, and do not affect the other points.
   */
  NeighborPerceiver(const Array<Vector3> points, float maxDistance);

  /**
   * Returns a list of neighboring points. Linear time to number of neighbors.
   * Can include some neighbors up to 2*sqrt(3) times the bin size, which always
   * equals the maximum distance. A non-finite query point has no neighbors.
   * The list is newly allocated on every call; if performance/fragmentation
   * is a concern, prefer NeighborPerceiver::getNeighborsInclusiveInPlace().
   *
   * @param point Position to return neighbors of, can be located anywhere.
   */
  Array<Index> getNeighborsInclusive(const Vector3& point) const;

  /**
   * Fills an array with all neighboring points. Linear time to number of
   * neighbors. Can include some neighbors up to 2*sqrt(3) times the bin size,
   * which always equals the maximum distance. A non-finite query point has no
   * neighbors.
   *
   * @param out Array to output neighbor indices in.
   * @param point Position to return neighbors of, can be located anywhere.
   */
  void getNeighborsInclusiveInPlace(Array<Index>& out,
                                    const Vector3& point) const;

private:
  /// Integer coordinates of a bin. Stored as 64-bit so that neighboring bins
  /// (cell +/- 1) can never overflow.
  using BinKey = std::array<int64_t, 3>;

  struct BinKeyHash
  {
    size_t operator()(const BinKey& key) const noexcept
    {
      // splitmix64-style mixing of the three components
      uint64_t h = 0x9e3779b97f4a7c15ULL;
      for (int64_t v : key) {
        h ^= static_cast<uint64_t>(v) + 0x9e3779b97f4a7c15ULL + (h << 6) +
             (h >> 2);
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= h >> 31;
      }
      return static_cast<size_t>(h);
    }
  };

  /// Computes the bin of a finite point. Returns false for non-finite points.
  bool getBinIndex(const Vector3& point, BinKey& key) const;

protected:
  float m_maxDistance;
  /// Edge length of the cubic bins. Always equal to m_maxDistance.
  double m_binSize;
  /// Only occupied bins are stored (sparse), in insertion order per bin.
  std::unordered_map<BinKey, std::vector<Index>, BinKeyHash> m_bins;
  /// Origin of the bin grid: the bounding box minimum of the finite points, or
  /// the origin if the extent is too large for a minimum-anchored grid.
  Vector3 m_anchor = Vector3::Zero();
  Vector3 m_minPos = Vector3::Zero();
  Vector3 m_maxPos = Vector3::Zero();
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_NEIGHBORPERCEIVER_H
