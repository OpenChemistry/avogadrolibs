/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/neighborperceiver.h>
#include <avogadro/core/vector.h>

using Avogadro::Core::Array;
using Avogadro::Core::NeighborPerceiver;
using Avogadro::Vector3;

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
