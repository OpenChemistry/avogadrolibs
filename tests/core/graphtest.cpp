/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/graph.h>

#include <algorithm>
#include <set>
#include <utility>
#include <vector>

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

TEST(GraphTest, degree)
{
  Graph graph(4);
  graph.addEdge(0, 1);
  graph.addEdge(0, 2);
  graph.addEdge(0, 3);

  EXPECT_EQ(graph.degree(0), static_cast<size_t>(3));
  EXPECT_EQ(graph.degree(1), static_cast<size_t>(1));
  EXPECT_EQ(graph.degree(3), static_cast<size_t>(1));
  // Out-of-range indices have no neighbors.
  EXPECT_EQ(graph.degree(4), static_cast<size_t>(0));
  EXPECT_EQ(graph.degree(100), static_cast<size_t>(0));
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

TEST(GraphTest, swapEdgeIndicesIgnoresIndicesThatAreNotEdges)
{
  // Undo commands reach swapEdgeIndices() with an edge index recorded before
  // the edit they reverse, so it can name an edge that no longer exists.
  // Indexing m_edgePairs with one of those reads past the end of the array and
  // then uses whatever it finds as a vertex index -- caught by the qtgui
  // rwmolecule fuzz target, and visible here only under a sanitizer.
  Graph graph(3);
  graph.addEdge(0, 1);

  graph.swapEdgeIndices(0, 5);
  graph.swapEdgeIndices(7, 0);
  graph.swapEdgeIndices(3, 4);
  // bondCount() - 1 on an empty bond list underflows, which is how the
  // fuzzer got here.
  graph.swapEdgeIndices(0, static_cast<size_t>(-1));

  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(1));
  expectConsistent(graph);
  EXPECT_EQ(graph.neighbors(0).size(), static_cast<size_t>(1));
  EXPECT_EQ(graph.neighbors(1).size(), static_cast<size_t>(1));
}

namespace {

// Stronger than expectConsistent(): every edge must appear in the incidence
// list of exactly its two endpoints, and the neighbor and incidence lists must
// agree in size.
void expectIncidenceConsistent(const Graph& graph)
{
  expectConsistent(graph);
  size_t total = 0;
  for (size_t v = 0; v < graph.size(); ++v) {
    const std::vector<size_t> edges = graph.edges(v);
    EXPECT_EQ(edges.size(), graph.neighbors(v).size()) << "vertex " << v;
    total += edges.size();
    for (size_t e : edges) {
      ASSERT_LT(e, graph.edgeCount());
      const auto ends = graph.endpoints(e);
      EXPECT_TRUE(ends.first == v || ends.second == v)
        << "edge " << e << " listed at vertex " << v;
      EXPECT_LT(ends.first, ends.second);
    }
  }
  EXPECT_EQ(total, 2 * graph.edgeCount());
}

std::vector<size_t> sorted(std::vector<size_t> v)
{
  std::sort(v.begin(), v.end());
  return v;
}

using Vec = std::vector<size_t>;

} // namespace

TEST(GraphTest, editEdgeInPlaceKeepsOtherEdges)
{
  // Star-ish graph: vertex 0 has edges 0..3, vertex 1 also has several.
  Graph graph(6);
  graph.addEdge(0, 1); // 0
  graph.addEdge(0, 2); // 1
  graph.addEdge(0, 3); // 2
  graph.addEdge(1, 4); // 3
  graph.addEdge(1, 5); // 4

  // Move edge 0 (0-1) to (4-5): both old endpoints keep other edges.
  ASSERT_TRUE(graph.editEdgeInPlace(0, 5, 4)); // reversed order on purpose
  expectIncidenceConsistent(graph);

  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(5));
  EXPECT_EQ(graph.endpoints(0), std::make_pair(size_t(4), size_t(5)));
  EXPECT_EQ(graph.endpoints(1), std::make_pair(size_t(0), size_t(2)));
  EXPECT_EQ(graph.endpoints(4), std::make_pair(size_t(1), size_t(5)));

  EXPECT_EQ(sorted(graph.edges(0)), (Vec{ 1, 2 }));
  EXPECT_EQ(sorted(graph.edges(1)), (Vec{ 3, 4 }));
  EXPECT_EQ(sorted(graph.edges(4)), (Vec{ 0, 3 }));
  EXPECT_EQ(sorted(graph.edges(5)), (Vec{ 0, 4 }));
  EXPECT_EQ(sorted(graph.neighbors(0)), (Vec{ 2, 3 }));
  EXPECT_EQ(sorted(graph.neighbors(1)), (Vec{ 4, 5 }));
  EXPECT_EQ(sorted(graph.neighbors(4)), (Vec{ 1, 5 }));
  EXPECT_EQ(sorted(graph.neighbors(5)), (Vec{ 1, 4 }));
  EXPECT_FALSE(graph.containsEdge(0, 1));
  EXPECT_TRUE(graph.containsEdge(4, 5));
}

TEST(GraphTest, editEdgeInPlaceSplitsAndMergesComponents)
{
  // Two chains: 0-1-2 and 3-4.
  Graph graph(5);
  graph.addEdge(0, 1); // 0
  graph.addEdge(1, 2); // 1
  graph.addEdge(3, 4); // 2
  ASSERT_EQ(graph.connectedComponents().size(), static_cast<size_t>(2));

  // Merge: move edge 1 (1-2) to (2-3). Components: {0,1} and {2,3,4}.
  ASSERT_TRUE(graph.editEdgeInPlace(1, 2, 3));
  expectIncidenceConsistent(graph);
  auto comps = graph.connectedComponents();
  ASSERT_EQ(comps.size(), static_cast<size_t>(2));
  std::set<std::set<size_t>> got(comps.begin(), comps.end());
  EXPECT_TRUE(got.count({ 0, 1 }));
  EXPECT_TRUE(got.count({ 2, 3, 4 }));

  // Merge everything: move edge 0 (0-1) to (0-4). One component, no splits.
  ASSERT_TRUE(graph.editEdgeInPlace(0, 0, 4));
  expectIncidenceConsistent(graph);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(2));
  // {0,2,3,4} and {1}: vertex 1 lost its only edge.
  EXPECT_EQ(graph.subgraphCount(0), static_cast<size_t>(4));
  EXPECT_EQ(graph.subgraphCount(1), static_cast<size_t>(1));

  // Split: move edge 2 (3-4) to (1-3)... that rejoins vertex 1.
  ASSERT_TRUE(graph.editEdgeInPlace(2, 1, 3));
  expectIncidenceConsistent(graph);
  comps = graph.connectedComponents();
  ASSERT_EQ(comps.size(), static_cast<size_t>(2));
  got = std::set<std::set<size_t>>(comps.begin(), comps.end());
  // Edges now: 0:(0,4) 1:(2,3) 2:(1,3)
  EXPECT_TRUE(got.count({ 0, 4 }));
  EXPECT_TRUE(got.count({ 1, 2, 3 }));
}

TEST(GraphTest, editEdgeInPlaceThenRemoveTerminates)
{
  Graph graph(5);
  graph.addEdge(0, 1);
  graph.addEdge(0, 2);
  graph.addEdge(0, 3);
  graph.addEdge(0, 4);
  ASSERT_TRUE(graph.editEdgeInPlace(0, 1, 2));
  ASSERT_TRUE(graph.editEdgeInPlace(2, 2, 3));
  expectIncidenceConsistent(graph);

  graph.removeEdges(0); // loops forever if the incidence lists are corrupt
  expectIncidenceConsistent(graph);
  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(2));

  graph.removeVertex(2);
  expectIncidenceConsistent(graph);
  graph.removeEdge(0);
  expectIncidenceConsistent(graph);
}

TEST(GraphTest, editEdgeInPlaceRefusesInvalidInput)
{
  Graph graph(4);
  graph.addEdge(0, 1);
  graph.addEdge(1, 2);
  graph.addEdge(2, 3);
  const auto pairs = graph.edgePairs();

  EXPECT_FALSE(graph.editEdgeInPlace(3, 0, 2)); // bad edge index
  EXPECT_FALSE(graph.editEdgeInPlace(0, 0, 4)); // bad vertex
  EXPECT_FALSE(graph.editEdgeInPlace(0, 9, 1)); // bad vertex
  EXPECT_FALSE(graph.editEdgeInPlace(0, 2, 2)); // self loop
  EXPECT_FALSE(graph.editEdgeInPlace(0, 2, 1)); // duplicate of edge 1
  EXPECT_FALSE(graph.editEdgeInPlace(0, 3, 2)); // duplicate of edge 2

  EXPECT_EQ(graph.edgeCount(), static_cast<size_t>(3));
  for (size_t i = 0; i < pairs.size(); ++i)
    EXPECT_EQ(graph.endpoints(i), pairs[i]);
  expectIncidenceConsistent(graph);
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));
}

TEST(GraphTest, editEdgeInPlaceSamePairIsNoOp)
{
  Graph graph(3);
  graph.addEdge(0, 1);
  graph.addEdge(1, 2);
  EXPECT_TRUE(graph.editEdgeInPlace(0, 0, 1));
  EXPECT_TRUE(graph.editEdgeInPlace(0, 1, 0));
  expectIncidenceConsistent(graph);
  EXPECT_EQ(graph.endpoints(0), std::make_pair(size_t(0), size_t(1)));
  EXPECT_EQ(graph.edges(1).size(), static_cast<size_t>(2));
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));
}

TEST(GraphTest, editEdgesInPlacePermutation)
{
  Graph graph(4);
  graph.addEdge(0, 1); // 0
  graph.addEdge(1, 2); // 1
  graph.addEdge(2, 3); // 2

  // Rotate the pairs; each single edit would collide with another edge.
  Avogadro::Core::Array<std::pair<size_t, size_t>> rotated;
  rotated.push_back({ 1, 2 });
  rotated.push_back({ 3, 2 });
  rotated.push_back({ 0, 1 });
  EXPECT_FALSE(graph.editEdgeInPlace(0, 1, 2));
  ASSERT_TRUE(graph.editEdgesInPlace(rotated));
  expectIncidenceConsistent(graph);
  EXPECT_EQ(graph.endpoints(0), std::make_pair(size_t(1), size_t(2)));
  EXPECT_EQ(graph.endpoints(1), std::make_pair(size_t(2), size_t(3)));
  EXPECT_EQ(graph.endpoints(2), std::make_pair(size_t(0), size_t(1)));
  EXPECT_EQ(graph.connectedComponents().size(), static_cast<size_t>(1));

  // Invalid sets change nothing.
  Avogadro::Core::Array<std::pair<size_t, size_t>> dup;
  dup.push_back({ 0, 1 });
  dup.push_back({ 1, 0 });
  dup.push_back({ 2, 3 });
  EXPECT_FALSE(graph.editEdgesInPlace(dup));
  Avogadro::Core::Array<std::pair<size_t, size_t>> shortSet;
  shortSet.push_back({ 0, 1 });
  EXPECT_FALSE(graph.editEdgesInPlace(shortSet));
  EXPECT_EQ(graph.endpoints(0), std::make_pair(size_t(1), size_t(2)));
  EXPECT_EQ(graph.endpoints(2), std::make_pair(size_t(0), size_t(1)));
  expectIncidenceConsistent(graph);
}

TEST(GraphTest, editEdgeInPlaceSamePairAfterVertexRemoval)
{
  // removeVertex() moves the last vertex into the hole without re-sorting the
  // stored endpoints, so an edge can be stored as (high, low). Editing it to
  // the pair it already joins must still succeed.
  Graph graph(4);
  graph.addEdge(2, 3);
  graph.removeVertex(0); // vertex 3 becomes vertex 0: stored as (2, 0)
  ASSERT_EQ(graph.edgeCount(), static_cast<size_t>(1));
  const auto ends = graph.endpoints(0);
  ASSERT_GT(ends.first, ends.second);
  EXPECT_TRUE(graph.editEdgeInPlace(0, ends.second, ends.first));
  EXPECT_TRUE(graph.editEdgeInPlace(0, ends.first, ends.second));
  EXPECT_EQ(graph.endpoints(0), std::make_pair(ends.second, ends.first));
  EXPECT_EQ(graph.edges(ends.first).size(), static_cast<size_t>(1));
  EXPECT_EQ(graph.edges(ends.second).size(), static_cast<size_t>(1));
}
