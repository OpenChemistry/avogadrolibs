/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/graph.h>

#include <algorithm>

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

TEST(GraphTest, removeVertexUpdatesLoneVertices)
{
  Graph graph(1);
  graph.removeVertex(0);
  EXPECT_EQ(graph.size(), static_cast<size_t>(0));
  EXPECT_EQ(graph.subgraphsCount(), static_cast<size_t>(0));
  EXPECT_TRUE(graph.connectedComponents().empty());
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

TEST(GraphTest, removeEdgesRemovesAllIncidentEdges)
{
  Graph graph(4);
  graph.addEdge(0, 1);
  graph.addEdge(0, 2);
  graph.addEdge(0, 3);

  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(3));

  graph.removeEdges(0);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(0));
  EXPECT_EQ(graph.degree(0), static_cast<size_t>(0));
  EXPECT_EQ(graph.degree(1), static_cast<size_t>(0));
  EXPECT_EQ(graph.degree(2), static_cast<size_t>(0));
  EXPECT_EQ(graph.degree(3), static_cast<size_t>(0));
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

namespace {

// Every edge must be findable from both of its endpoints, and no vertex may
// list itself. A graph that fails this looks fine by edge count while
// removeEdge() quietly does nothing.
void expectConsistent(const Graph& graph)
{
  for (size_t v = 0; v < graph.size(); ++v) {
    for (size_t n : graph.neighbors(v))
      EXPECT_NE(v, n) << "vertex " << v << " lists itself as a neighbour";
  }

  for (size_t e = 0; e < graph.edgeCount(); ++e) {
    const std::pair<size_t, size_t> ends = graph.endpoints(e);
    const std::vector<size_t>& first = graph.neighbors(ends.first);
    const std::vector<size_t>& second = graph.neighbors(ends.second);
    EXPECT_NE(std::find(first.begin(), first.end(), ends.second), first.end())
      << "edge (" << ends.first << "," << ends.second << ") missing from "
      << ends.first << "'s neighbours";
    EXPECT_NE(std::find(second.begin(), second.end(), ends.first), second.end())
      << "edge (" << ends.first << "," << ends.second << ") missing from "
      << ends.second << "'s neighbours";
  }
}

} // namespace

TEST(GraphTest, swapVertexIndicesUnconnectedPair)
{
  Graph graph(4);
  graph.addEdge(0, 1);
  graph.addEdge(2, 3);

  graph.swapVertexIndices(0, 2);
  expectConsistent(graph);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(2));
}

// The two vertices being bonded to each other is the case that used to
// break: both loops skip the reference they hold to one another, and the
// swap then leaves each naming itself. A z-matrix renumbering swaps bonded
// atoms constantly, so this is not an exotic input.
TEST(GraphTest, swapVertexIndicesBondedPair)
{
  Graph graph(3);
  graph.addEdge(0, 1);
  graph.addEdge(1, 2);

  graph.swapVertexIndices(0, 1);

  expectConsistent(graph);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(2));

  // The vertex that was 1, carrying two edges, is now 0.
  EXPECT_EQ(graph.neighbors(0).size(), static_cast<size_t>(2));
  EXPECT_EQ(graph.neighbors(1).size(), static_cast<size_t>(1));
  EXPECT_EQ(graph.neighbors(2).size(), static_cast<size_t>(1));

  // And the edge between them can still be removed, which is what the
  // corruption prevented.
  graph.removeEdge(0, 1);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(1));
  expectConsistent(graph);
}

TEST(GraphTest, swapVertexIndicesBondedPairInARing)
{
  Graph graph(4);
  for (size_t k = 0; k < 4; ++k)
    graph.addEdge(k, (k + 1) % 4);

  graph.swapVertexIndices(1, 2);
  expectConsistent(graph);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(4));
  for (size_t v = 0; v < 4; ++v)
    EXPECT_EQ(graph.neighbors(v).size(), static_cast<size_t>(2))
      << "vertex " << v;
}
