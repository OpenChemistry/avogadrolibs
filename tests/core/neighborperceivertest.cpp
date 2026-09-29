/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/core/vector.h>

#include <algorithm>
#include <limits>
#include <random>

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::NeighborPerceiver;

TEST(NeighborPerceiverTest, positive)
{
  Array<Vector3> points;
  points.push_back(Vector3(0.0, 0.0, 0.0));
  points.push_back(Vector3(1.0, 0.0, 0.0));
  points.push_back(Vector3(0.0, 1.5, 1.5));
  points.push_back(Vector3(2.1, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 1.0f);

  auto neighbors = perceiver.getNeighborsInclusive(Vector3(0.0, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(3));
}

TEST(NeighborPerceiverTest, negative)
{
  Array<Vector3> points;
  points.push_back(Vector3(0.0, 0.0, 0.0));
  points.push_back(Vector3(-1.0, 0.0, 0.0));
  points.push_back(Vector3(0.0, -1.5, -1.5));
  points.push_back(Vector3(-2.1, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 1.0f);

  auto neighbors = perceiver.getNeighborsInclusive(Vector3(0.0, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(3));
}

TEST(NeighborPerceiverTest, bounds)
{
  Array<Vector3> points;
  points.push_back(Vector3(0.0, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 1.0f);

  auto neighbors = perceiver.getNeighborsInclusive(Vector3(0.0, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(1));
  perceiver.getNeighborsInclusiveInPlace(neighbors, Vector3(1.5, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(1));
  perceiver.getNeighborsInclusiveInPlace(neighbors, Vector3(2.5, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(0));
  perceiver.getNeighborsInclusiveInPlace(neighbors, Vector3(-0.5, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(1));
  perceiver.getNeighborsInclusiveInPlace(neighbors, Vector3(-1.5, 0.0, 0.0));
  EXPECT_EQ(neighbors.size(), static_cast<size_t>(0));
}

namespace {

bool contains(const Array<Avogadro::Index>& list, Avogadro::Index index)
{
  return std::find(list.begin(), list.end(), index) != list.end();
}

} // namespace

TEST(NeighborPerceiverTest, longChain)
{
  // 5000 points spaced 1 apart with maxDistance 1.5 need ~3334 bins along x,
  // beyond the per-axis limit. Neighbors at the far end used to be lost.
  Array<Vector3> points;
  for (int i = 0; i < 5000; ++i)
    points.push_back(Vector3(i, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 1.5f);

  int missing = 0;
  Array<Avogadro::Index> neighbors;
  for (Avogadro::Index i = 0; i < points.size(); ++i) {
    perceiver.getNeighborsInclusiveInPlace(neighbors, points[i]);
    if (i > 0 && !contains(neighbors, i - 1))
      ++missing;
    if (i + 1 < points.size() && !contains(neighbors, i + 1))
      ++missing;
  }
  EXPECT_EQ(missing, 0);
}

TEST(NeighborPerceiverTest, largeBox)
{
  // Pairs at the corners of a 700 A cube with maxDistance 2 need 350^3 bins,
  // beyond the total limit. Every query used to return nothing.
  Array<Vector3> points;
  for (int corner = 0; corner < 8; ++corner) {
    Vector3 origin((corner & 1) ? 700.0 : 0.0, (corner & 2) ? 700.0 : 0.0,
                   (corner & 4) ? 700.0 : 0.0);
    points.push_back(origin);
    points.push_back(origin + Vector3(1.0, 0.0, 0.0));
  }

  NeighborPerceiver perceiver(points, 2.0f);

  for (Avogadro::Index i = 0; i < points.size(); ++i) {
    const Avogadro::Index partner = i ^ 1;
    auto neighbors = perceiver.getNeighborsInclusive(points[i]);
    EXPECT_TRUE(contains(neighbors, partner)) << i;
    EXPECT_TRUE(contains(neighbors, i)) << i;
  }
}

TEST(NeighborPerceiverTest, hugeCoordinates)
{
  // Coordinates this large used to be cast to int in the bin index (UB).
  Array<Vector3> points;
  points.push_back(Vector3(0.0, 0.0, 0.0));
  points.push_back(Vector3(1.0e12, 0.0, 0.0));
  points.push_back(Vector3(1.0e12 + 1.0, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 2.0f);

  auto neighbors = perceiver.getNeighborsInclusive(points[1]);
  EXPECT_TRUE(contains(neighbors, 2));
  neighbors = perceiver.getNeighborsInclusive(points[2]);
  EXPECT_TRUE(contains(neighbors, 1));

  // extreme values that would overflow an int even after division
  Array<Vector3> extreme;
  extreme.push_back(Vector3(-1.0e300, 0.0, 0.0));
  extreme.push_back(Vector3(1.0e300, 0.0, 0.0));
  NeighborPerceiver extremePerceiver(extreme, 2.0f);
  extremePerceiver.getNeighborsInclusive(Vector3(4.87e307, 0.0, 0.0));
}

TEST(NeighborPerceiverTest, queryOutsideBox)
{
  Array<Vector3> points;
  points.push_back(Vector3(0.0, 0.0, 0.0));
  points.push_back(Vector3(1.0, 1.0, 1.0));
  points.push_back(Vector3(2.0, 0.0, 0.0));

  NeighborPerceiver perceiver(points, 1.5f);

  const double nan = std::numeric_limits<double>::quiet_NaN();
  const double inf = std::numeric_limits<double>::infinity();
  const Vector3 queries[] = {
    Vector3(1e6, 0.0, 0.0), Vector3(-1e6, -1e6, -1e6), Vector3(1e300, 0.0, 0.0),
    Vector3(nan, 0.0, 0.0), Vector3(0.0, nan, nan),    Vector3(inf, -inf, 0.0)
  };
  for (const Vector3& query : queries) {
    auto neighbors = perceiver.getNeighborsInclusive(query);
    for (auto index : neighbors)
      EXPECT_LT(index, points.size());
    // nothing binned is anywhere near these
    EXPECT_TRUE(neighbors.empty());
  }
}

TEST(NeighborPerceiverTest, matchesBruteForce)
{
  // An ordinary cloud: every point strictly within maxDistance must be found.
  std::mt19937 rng(12345);
  std::uniform_real_distribution<double> dist(-10.0, 10.0);
  Array<Vector3> points;
  for (int i = 0; i < 300; ++i)
    points.push_back(Vector3(dist(rng), dist(rng), dist(rng)));

  const float maxDistance = 2.5f;
  NeighborPerceiver perceiver(points, maxDistance);

  Array<Avogadro::Index> neighbors;
  for (Avogadro::Index i = 0; i < points.size(); ++i) {
    perceiver.getNeighborsInclusiveInPlace(neighbors, points[i]);
    for (Avogadro::Index j = 0; j < points.size(); ++j) {
      if ((points[j] - points[i]).norm() < maxDistance)
        EXPECT_TRUE(contains(neighbors, j)) << i << " " << j;
    }
  }
}
