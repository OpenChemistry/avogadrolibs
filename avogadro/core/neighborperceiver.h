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
#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class NeighborPerceiver neighborperceiver.h <avogadro/core/neighborperceiver.h>
 * @brief This class can be used to find physically neighboring points in linear average time.
 */
class AVOGADROCORE_EXPORT NeighborPerceiver
{
public:
  /**
   * Creates a NeighborPerceiver that detects neighbors up to at least some distance.
   *
   * @param points Positions in 3D space to detect neighbors among.
   * @param maxDistance All neighbors strictly within this distance will be detected.
   *                    Should be as low as possible for best performance.
   */
  NeighborPerceiver(const Array<Vector3> points, float maxDistance);
  
  /**
   * Returns a list of neighboring points. Linear time to number of neighbors.
   * Can include some neighbors up to 2*sqrt(3) times the maximum distance.
   * The list is newly allocated on every call; if performance/fragmentation
   * is a concern, prefer NeighborPerceiver::getNeighborsInclusiveInPlace().
   *
   * @param point Position to return neighbors of, can be located anywhere.
   */
  Array<Index> getNeighborsInclusive(const Vector3 &point) const;
  
  /**
   * Fills an array with all neighboring points. Linear time to number of neighbors.
   * Can include some neighbors up to 2*sqrt(3) times the maximum distance.
   *
   * @param out Array to output neighbor indices in.
   * @param point Position to return neighbors of, can be located anywhere.
   */
  void getNeighborsInclusiveInPlace(Array<Index> &out, const Vector3 &point) const;
  
private:
  std::array<int, 3> getBinIndex(const Vector3 &point) const;
protected:
  float m_maxDistance;
  std::array<int, 3> m_binCount;
  std::vector<std::vector<std::vector<std::vector<Index>>>> m_bins;
  Vector3 m_minPos;
  Vector3 m_maxPos;
  mutable Array<Index> *m_cachedArray;
  mutable std::array<int, 3> m_cachedIndex;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_NEIGHBORPERCEIVER_H
