/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/graph.h>

using Avogadro::Core::Graph;

TEST(GraphTest, size)
{
  Graph graph;
  EXPECT_EQ(graph.size(), static_cast<size_t>(0));

  Graph graph2(12);
  EXPECT_EQ(graph2.size(), static_cast<size_t>(12));
}

TEST(GraphTest, setSize)
{
  Graph graph;
  EXPECT_EQ(graph.size(), static_cast<size_t>(0));

  graph.setSize(100);
  EXPECT_EQ(graph.size(), static_cast<size_t>(100));

  graph.setSize(50);
  EXPECT_EQ(graph.size(), static_cast<size_t>(50));
}

TEST(GraphTest, isEmpty)
{
  Graph graph;
  EXPECT_EQ(graph.isEmpty(), true);

  graph.addVertex();
  EXPECT_EQ(graph.isEmpty(), false);

  graph.clear();
  EXPECT_EQ(graph.isEmpty(), true);
}

TEST(GraphTest, clear) {}

TEST(GraphTest, addVertex)
{
  Graph graph;
  size_t index = graph.addVertex();
  EXPECT_EQ(index, 0);
  EXPECT_EQ(graph.size(), static_cast<size_t>(1));

  index = graph.addVertex();
  EXPECT_EQ(index, 1);

  index = graph.addVertex();
  EXPECT_EQ(index, 2);
}

TEST(GraphTest, removeVertex)
{
  Graph graph(4);
  EXPECT_EQ(graph.size(), static_cast<size_t>(4));

  graph.removeVertex(0);
  EXPECT_EQ(graph.size(), static_cast<size_t>(3));

  graph.removeVertex(2);
  EXPECT_EQ(graph.size(), static_cast<size_t>(2));
}

TEST(GraphTest, vertexCount)
{
  Graph graph;
  EXPECT_EQ(graph.vertexCount(), static_cast<size_t>(0));

  graph.addVertex();
  EXPECT_EQ(graph.vertexCount(), static_cast<size_t>(1));

  graph.addVertex();
  EXPECT_EQ(graph.vertexCount(), static_cast<size_t>(2));

  graph.removeVertex(1);
  EXPECT_EQ(graph.vertexCount(), static_cast<size_t>(1));

  graph.clear();
  EXPECT_EQ(graph.vertexCount(), static_cast<size_t>(0));
}

TEST(GraphTest, addEdge)
{
  Graph graph(5);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(0));

  graph.addEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), 1);
  EXPECT_EQ(graph.containsEdge(0, 1), true);

  graph.addEdge(1, 4);
  EXPECT_EQ(graph.edgeCount(), 2);
  EXPECT_EQ(graph.containsEdge(1, 4), true);
}

TEST(GraphTest, removeEdge)
{
  Graph graph(5);
  graph.addEdge(0, 1);
  graph.addEdge(1, 4);
}

TEST(GraphTest, edgeCount)
{
  Graph graph(3);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(0));

  graph.addEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(1));

  graph.addEdge(0, 2);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(2));

  graph.addEdge(1, 2);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(3));

  graph.removeEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(2));

  graph.clear();
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(0));
}

TEST(GraphTest, connectedComponents)
{
  Graph graph(6);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(6));

  graph.addEdge(0, 1);
  graph.addEdge(1, 2);
  graph.addEdge(3, 4);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(3));

  graph.addEdge(4, 5);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(2));

  graph.addEdge(3, 2);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));

  graph.addEdge(1, 4);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));

  graph.removeEdge(2, 3);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));

  graph.removeEdges(4);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(4));
}
