/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "graph.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <set>
#include <stack>
#include <utility>

namespace Avogadro::Core {

Graph::Graph(size_t n) : m_adjacencyList(n), m_edgeMap(n), m_vertexToSubgraph(n)
{
  for (size_t i = 0; i < n; i++) {
    m_vertexToSubgraph[i] = -1;
    m_loneVertices.insert(i);
  }
}

void Graph::setSize(size_t n)
{
  // If the graph is being made smaller we first need to remove all of the edges
  // from the soon to be removed vertices.
  for (size_t i = n; i < m_adjacencyList.size(); ++i) {
    removeEdges(i);
    // Mark subgraph as dirty if vertex has one assigned
    if (m_vertexToSubgraph[i] >= 0)
      m_subgraphDirty[m_vertexToSubgraph[i]] = true;
  }
  m_vertexToSubgraph.resize(n);
  // Mark the new nodes as isolated, with no explicit subgraph
  for (size_t i = m_adjacencyList.size(); i < n; ++i) {
    m_vertexToSubgraph[i] = -1;
    m_loneVertices.insert(i);
  }

  m_adjacencyList.resize(n);
  m_edgeMap.resize(n);
}

size_t Graph::size() const
{
  return vertexCount();
}

bool Graph::isEmpty() const
{
  return m_adjacencyList.empty();
}

void Graph::clear()
{
  m_adjacencyList.clear();
  m_edgeMap.clear();
  m_edgePairs.clear();
  m_vertexToSubgraph.clear();
  m_subgraphToVertices.clear();
  m_subgraphDirty.clear();
}

size_t Graph::addVertex()
{
  setSize(size() + 1);
  return size() - 1;
}

void Graph::removeVertex(size_t index)
{
  // invalid request, skip it
  if (index >= size())
    return;

  // Mark the subgraph as dirty, leave the work for later
  if (m_vertexToSubgraph[index] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[index]] = true;
  // Remove the edges to the vertex.
  removeEdges(index);
  // The vertex is being removed entirely, so it should no longer be tracked
  // as a lone vertex.
  m_loneVertices.erase(index);

  // Swap with last vertex.
  if (index < size() - 1) {
    std::swap(m_adjacencyList[index], m_adjacencyList.back());
    size_t affectedIndex = m_adjacencyList.size() - 1;
    // NOLINTBEGIN(*)
    for (size_t i = 0; i < m_adjacencyList[index].size(); i++) {
      size_t otherIndex = m_adjacencyList[index][i];
      for (size_t j = 0; j < m_adjacencyList[otherIndex].size(); j++) {
        if (m_adjacencyList[otherIndex][j] == affectedIndex)
          m_adjacencyList[otherIndex][j] = index;
      }
    }
    // NOLINTEND(*)
    std::swap(m_edgeMap[index], m_edgeMap.back());
    for (size_t i = 0; i < m_edgeMap[index].size(); i++) {
      size_t edgeIndex = m_edgeMap[index][i];
      if (m_edgePairs[edgeIndex].first == affectedIndex)
        m_edgePairs[edgeIndex].first = index;
      if (m_edgePairs[edgeIndex].second == affectedIndex)
        m_edgePairs[edgeIndex].second = index;
    }
    if (m_vertexToSubgraph[index] >= 0)
      m_subgraphToVertices[m_vertexToSubgraph[index]].erase(index);
    std::swap(m_vertexToSubgraph[index], m_vertexToSubgraph.back());
    if (m_vertexToSubgraph[index] >= 0) {
      m_subgraphToVertices[m_vertexToSubgraph[index]].erase(affectedIndex);
      m_subgraphToVertices[m_vertexToSubgraph[index]].insert(index);
    }
    if (m_loneVertices.erase(affectedIndex) > 0)
      m_loneVertices.insert(index);
  }
  m_adjacencyList.pop_back();
  m_edgeMap.pop_back();
  m_vertexToSubgraph.pop_back();
}

void Graph::swapVertexIndices(size_t a, size_t b)
{
  // Swap all references to a and b in m_adjacencyList
  for (size_t i = 0; i < m_adjacencyList[a].size(); i++) {
    size_t otherIndex = m_adjacencyList[a][i];
    if (otherIndex == b)
      continue;
    // NOLINTBEGIN(*)
    for (size_t j = 0; j < m_adjacencyList[otherIndex].size(); j++) {
      if (m_adjacencyList[otherIndex][j] == a) {
        m_adjacencyList[otherIndex][j] = b;
        break;
      }
    }
    // NOLINTEND(*)
  }
  for (size_t i = 0; i < m_adjacencyList[b].size(); i++) {
    size_t otherIndex = m_adjacencyList[b][i];
    if (otherIndex == a)
      continue;
    // NOLINTBEGIN(*)
    for (size_t j = 0; j < m_adjacencyList[otherIndex].size(); j++) {
      if (m_adjacencyList[otherIndex][j] == b) {
        m_adjacencyList[otherIndex][j] = a;
        break;
      }
    }
    // NOLINTEND(*)
  }

  std::swap(m_adjacencyList[a], m_adjacencyList[b]);

  // The two loops above skip the reference a and b hold to each other, since
  // rewriting it there would immediately be undone by the other loop. The
  // swap has just carried those entries to the opposite vertex, where each
  // now names its own vertex, so they are corrected here. Left alone, both
  // vertices list themselves as neighbours and the edge between them can no
  // longer be found in the adjacency list -- which makes removeEdge() return
  // without removing anything while its caller goes on to drop the matching
  // bond order.
  for (auto& neighbor : m_adjacencyList[a]) {
    if (neighbor == a)
      neighbor = b;
  }
  for (auto& neighbor : m_adjacencyList[b]) {
    if (neighbor == b)
      neighbor = a;
  }

  // Update m_edgePairs using info from m_edgeMap
  for (size_t i = 0; i < m_edgeMap[a].size(); i++) {
    size_t edgeIndex = m_edgeMap[a][i];
    if (m_edgePairs[edgeIndex].first == a) {
      m_edgePairs[edgeIndex].first = b;
      if (m_edgePairs[edgeIndex].second == b)
        m_edgePairs[edgeIndex].second = a;
    }
    if (m_edgePairs[edgeIndex].second == a) {
      m_edgePairs[edgeIndex].second = b;
      if (m_edgePairs[edgeIndex].first == b)
        m_edgePairs[edgeIndex].first = a;
    }
  }
  for (size_t i = 0; i < m_edgeMap[b].size(); i++) {
    size_t edgeIndex = m_edgeMap[b][i];
    if (m_edgePairs[edgeIndex].first == b && m_edgePairs[edgeIndex].second != a)
      m_edgePairs[edgeIndex].first = a;
    if (m_edgePairs[edgeIndex].second == b && m_edgePairs[edgeIndex].first != a)
      m_edgePairs[edgeIndex].second = a;
  }

  std::swap(m_edgeMap[a], m_edgeMap[b]);
}

size_t Graph::vertexCount() const
{
  return m_adjacencyList.size();
}

size_t Graph::addEdge(size_t a, size_t b)
{
  assert(a < size());
  assert(b < size());
  if (b < a)
    std::swap(a, b);
  std::vector<size_t>& neighborsA = m_adjacencyList[a];
  std::vector<size_t>& neighborsB = m_adjacencyList[b];

  // Ensure edge does not exist already.
  if (std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end()) {
    // NOLINTBEGIN(*)
    for (size_t i = 0; i < m_edgeMap[a].size(); i++) {
      size_t edgeIndex = m_edgeMap[a][i];
      if (m_edgePairs[edgeIndex].first == b ||
          m_edgePairs[edgeIndex].second == b)
        return edgeIndex;
    }
    // NOLINTEND(*)
  }

  // Merge subgraphs
  joinSubgraphs(a, b);

  // Add the edge to each vertex' adjacency list.
  neighborsA.push_back(b);
  neighborsB.push_back(a);

  // Add the edge to each vertex' incident edge list.
  size_t newEdgeIndex = edgeCount();
  m_edgeMap[a].push_back(newEdgeIndex);
  m_edgeMap[b].push_back(newEdgeIndex);

  m_edgePairs.push_back(std::pair<size_t, size_t>(a, b));

  return newEdgeIndex;
}

void Graph::joinSubgraphs(size_t a, size_t b) const
{
  int subgraphA = m_vertexToSubgraph[a];
  int subgraphB = m_vertexToSubgraph[b];
  if (subgraphA < 0 && subgraphB < 0) {
    int newSubgraph = createNewSubgraph();
    m_vertexToSubgraph[a] = newSubgraph;
    m_vertexToSubgraph[b] = newSubgraph;
    m_subgraphToVertices[newSubgraph].insert(a);
    m_subgraphToVertices[newSubgraph].insert(b);
    m_loneVertices.erase(a);
    m_loneVertices.erase(b);
  } else if (subgraphA < 0) {
    m_vertexToSubgraph[a] = subgraphB;
    m_subgraphToVertices[subgraphB].insert(a);
    m_loneVertices.erase(a);
  } else if (subgraphB < 0) {
    m_vertexToSubgraph[b] = subgraphA;
    m_subgraphToVertices[subgraphA].insert(b);
    m_loneVertices.erase(b);
  } else if (subgraphA != subgraphB) {
    m_subgraphDirty[subgraphA] =
      m_subgraphDirty[subgraphA] || m_subgraphDirty[subgraphB];
    for (size_t i : m_subgraphToVertices[subgraphB]) {
      m_subgraphToVertices[subgraphA].insert(i);
      if (i < m_vertexToSubgraph.size())
        m_vertexToSubgraph[i] = subgraphA;
      else
        m_vertexToSubgraph.push_back(subgraphA);
    }
    // Just leave it empty, it could be reused
    m_subgraphToVertices[subgraphB].clear();
  }
}

std::set<size_t> Graph::checkConectivity(size_t a, size_t b) const
{
  if (a == b) {
    return std::set<size_t>();
  }
  std::set<size_t> visited;
  bool connected = false;
  std::stack<size_t> nextNeighbors;
  visited.insert(a);
  nextNeighbors.push(a);

  while (!nextNeighbors.empty()) {
    size_t visiting = nextNeighbors.top();
    visited.insert(visiting);
    nextNeighbors.pop();
    const std::vector<size_t>& neighbors = m_adjacencyList[visiting];
    for (const auto& n : neighbors) {
      if (visiting == b) {
        connected = true;
      }
      if (visited.find(n) == visited.end()) {
        visited.insert(n);
        nextNeighbors.push(n);
      }
    }
  }
  if (connected) {
    return std::set<size_t>();
  }
  return visited;
}

void Graph::removeEdge(size_t a, size_t b)
{
  if (a >= size() || b >= size())
    return;

  std::vector<size_t>& neighborsA = m_adjacencyList[a];
  std::vector<size_t>& neighborsB = m_adjacencyList[b];

  auto iter = std::find(neighborsA.begin(), neighborsA.end(), b);

  if (iter == neighborsA.end())
    return;

  std::swap(*iter, neighborsA.back());
  neighborsA.pop_back();
  // std::find() returns end() when the element is absent, and dereferencing
  // that writes past the end of the vector. a is only guaranteed to be in
  // neighborsB if the adjacency lists agree with each other, which is exactly
  // what is not true once anything has corrupted them.
  auto iterB = std::find(neighborsB.begin(), neighborsB.end(), a);
  if (iterB != neighborsB.end()) {
    std::swap(*iterB, neighborsB.back());
    neighborsB.pop_back();
  }

  size_t edgeIndex = 0;
  for (size_t i = 0; i < m_edgeMap[a].size(); i++) {
    edgeIndex = m_edgeMap[a][i];
    const std::pair<size_t, size_t>& pair = m_edgePairs[edgeIndex];
    if (pair.first == b || pair.second == b) {
      std::swap(m_edgeMap[a][i], m_edgeMap[a].back());
      m_edgeMap[a].pop_back();
      break;
    }
  }

  for (size_t i = 0; i < m_edgeMap[b].size(); i++) {
    if (m_edgeMap[b][i] == edgeIndex) {
      std::swap(m_edgeMap[b][i], m_edgeMap[b].back());
      m_edgeMap[b].pop_back();
      break;
    }
  }

  std::swap(m_edgePairs[edgeIndex], m_edgePairs.back());
  m_edgePairs.pop_back();

  size_t affectedIndex = m_edgePairs.size();
  if (affectedIndex != edgeIndex) {
    // The edge that was at the back now lives at edgeIndex, so both of its
    // endpoints have to be told. Same trap as above: std::find() returns
    // end() if the endpoint's list does not mention the old index, and
    // assigning through that end() iterator is an out-of-bounds write -- one
    // that silently corrupts whatever follows the vector, including the
    // bookkeeping this function depends on next time round.
    std::vector<size_t>& edgeList1 = m_edgeMap[m_edgePairs[edgeIndex].first];
    auto found1 = std::find(edgeList1.begin(), edgeList1.end(), affectedIndex);
    if (found1 != edgeList1.end())
      *found1 = edgeIndex;
    std::vector<size_t>& edgeList2 = m_edgeMap[m_edgePairs[edgeIndex].second];
    auto found2 = std::find(edgeList2.begin(), edgeList2.end(), affectedIndex);
    if (found2 != edgeList2.end())
      *found2 = edgeIndex;
  }

  // Mark the subgraph as dirty, leave the work for later
  if (m_vertexToSubgraph[a] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[a]] = true;
}

void Graph::removeEdge(size_t edgeIndex)
{
  if (edgeIndex >= edgeCount())
    return;

  const std::pair<size_t, size_t>& pair = m_edgePairs[edgeIndex];
  removeEdge(pair.first, pair.second);
}

void Graph::removeEdges()
{
  for (size_t i = 0; i < m_adjacencyList.size(); ++i) {
    m_adjacencyList[i].clear();
    m_edgeMap[i].clear();
    m_vertexToSubgraph[i] = -1;
    m_loneVertices.insert(i);
  }
  m_edgePairs.clear();
  m_subgraphToVertices.clear();
  m_subgraphDirty.clear();
}

void Graph::removeEdges(size_t index)
{
  if (index >= size())
    return;

  // Mark the subgraph as dirty, leave the work for later
  const int subgraph = m_vertexToSubgraph[index];
  if (subgraph >= 0) {
    m_subgraphDirty[subgraph] = true;
    m_subgraphToVertices[subgraph].erase(index);
  }

  m_vertexToSubgraph[index] = -1;
  m_loneVertices.insert(index);

  // Removing edges mutates m_edgeMap[index], so consume until empty -- but
  // removeEdge() has three paths that return having removed nothing (an index
  // past edgeCount(), and either endpoint check failing), and this loop's only
  // exit is the list becoming empty. Ignoring that spins here forever, which
  // is how a 921-byte fuzz input took 41 seconds. Drop an entry that
  // removeEdge() would not, so the loop always makes progress: the entry
  // refers to an edge the edge list no longer agrees exists, and this vertex
  // is losing its edges either way.
  while (!m_edgeMap[index].empty()) {
    const size_t before = m_edgeMap[index].size();
    removeEdge(m_edgeMap[index].back());
    if (m_edgeMap[index].size() >= before)
      m_edgeMap[index].pop_back();
  }
}

bool Graph::editEdgeInPlace(size_t edgeIndex, size_t a, size_t b)
{
  if (edgeIndex >= m_edgePairs.size() || a >= size() || b >= size() || a == b)
    return false;
  if (b < a)
    std::swap(a, b);

  const std::pair<size_t, size_t> oldPair = m_edgePairs[edgeIndex];
  // removeVertex() can leave a stored pair with first > second, so compare
  // the endpoints as an unordered pair.
  if ((oldPair.first == a && oldPair.second == b) ||
      (oldPair.first == b && oldPair.second == a)) {
    m_edgePairs[edgeIndex] = std::pair<size_t, size_t>(a, b);
    return true;
  }

  // Refuse to create a duplicate edge (the old edge is a different pair, so
  // any existing a-b connection is some other edge).
  const std::vector<size_t>& neighborsA = m_adjacencyList[a];
  if (std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end())
    return false;

  // Detach exactly the old edge from both endpoints.
  auto eraseValue = [](std::vector<size_t>& list, size_t value) {
    auto iter = std::find(list.begin(), list.end(), value);
    if (iter != list.end()) {
      std::swap(*iter, list.back());
      list.pop_back();
    }
  };
  eraseValue(m_edgeMap[oldPair.first], edgeIndex);
  eraseValue(m_edgeMap[oldPair.second], edgeIndex);
  eraseValue(m_adjacencyList[oldPair.first], oldPair.second);
  eraseValue(m_adjacencyList[oldPair.second], oldPair.first);

  // The old connection may have been the only link inside its component.
  // Mark it dirty and let the lazy split pass sort it out, as removeEdge does.
  if (m_vertexToSubgraph[oldPair.first] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[oldPair.first]] = true;

  // Attach the new edge, merging components as addEdge does.
  joinSubgraphs(a, b);
  m_adjacencyList[a].push_back(b);
  m_adjacencyList[b].push_back(a);
  m_edgeMap[a].push_back(edgeIndex);
  m_edgeMap[b].push_back(edgeIndex);
  m_edgePairs[edgeIndex] = std::pair<size_t, size_t>(a, b);
  return true;
}

bool Graph::editEdgesInPlace(const Array<std::pair<size_t, size_t>>& pairs)
{
  if (pairs.size() != m_edgePairs.size())
    return false;

  // Validate the final set as a whole; intermediate states do not matter.
  Array<std::pair<size_t, size_t>> normalized(pairs);
  std::set<std::pair<size_t, size_t>> seen;
  for (size_t i = 0; i < normalized.size(); ++i) {
    std::pair<size_t, size_t>& pair = normalized[i];
    if (pair.first >= size() || pair.second >= size() ||
        pair.first == pair.second)
      return false;
    if (pair.second < pair.first)
      std::swap(pair.first, pair.second);
    if (!seen.insert(pair).second)
      return false;
  }

  // Rebuild the adjacency, incidence and component data from scratch,
  // keeping the edge indices.
  removeEdges();
  for (size_t i = 0; i < normalized.size(); ++i) {
    const size_t a = normalized[i].first;
    const size_t b = normalized[i].second;
    joinSubgraphs(a, b);
    m_adjacencyList[a].push_back(b);
    m_adjacencyList[b].push_back(a);
    m_edgeMap[a].push_back(i);
    m_edgeMap[b].push_back(i);
    m_edgePairs.push_back(normalized[i]);
  }
  return true;
}

void Graph::swapEdgeIndices(size_t edgeIndex1, size_t edgeIndex2)
{
  // Undo commands hold edge indices recorded before the edit they reverse, so
  // an index can arrive here that is no longer an edge -- see removeEdge(),
  // which carries real checks for the same reason. Indexing m_edgePairs with
  // one of those reads past the end and then uses whatever it found as a
  // vertex index into m_edgeMap.
  if (edgeIndex1 >= m_edgePairs.size() || edgeIndex2 >= m_edgePairs.size())
    return;

  // Find the 4 endpoints of both edges.
  const std::pair<size_t, size_t>& pair1 = m_edgePairs[edgeIndex1];
  if (pair1.first >= m_edgeMap.size() || pair1.second >= m_edgeMap.size())
    return;
  std::array<size_t*, 2> changeTo2 = { nullptr, nullptr };
  // NOLINTBEGIN(*)
  for (size_t i = 0; i < m_edgeMap[pair1.first].size(); i++) {
    if (m_edgeMap[pair1.first][i] == edgeIndex1) {
      changeTo2[0] = &m_edgeMap[pair1.first][i];
    }
  }
  for (size_t i = 0; i < m_edgeMap[pair1.second].size(); i++) {
    if (m_edgeMap[pair1.second][i] == edgeIndex1) {
      changeTo2[1] = &m_edgeMap[pair1.second][i];
    }
  }
  const std::pair<size_t, size_t>& pair2 = m_edgePairs[edgeIndex2];
  if (pair2.first >= m_edgeMap.size() || pair2.second >= m_edgeMap.size())
    return;
  std::array<size_t*, 2> changeTo1 = { nullptr, nullptr };
  for (size_t i = 0; i < m_edgeMap[pair2.first].size(); i++) {
    if (m_edgeMap[pair2.first][i] == edgeIndex2) {
      changeTo1[0] = &m_edgeMap[pair2.first][i];
    }
  }
  for (size_t i = 0; i < m_edgeMap[pair2.second].size(); i++) {
    if (m_edgeMap[pair2.second][i] == edgeIndex2) {
      changeTo1[1] = &m_edgeMap[pair2.second][i];
    }
  }
  // NOLINTEND(*)

  /*
  Swap m_edgeMap values only after reading everything, to avoid race condition.
  */
  if (changeTo2[0] && changeTo2[1]) {
    *changeTo2[0] = edgeIndex2;
    *changeTo2[1] = edgeIndex2;
  }
  if (changeTo1[0] && changeTo1[1]) {
    *changeTo1[0] = edgeIndex1;
    *changeTo1[1] = edgeIndex1;
  }

  std::swap(m_edgePairs[edgeIndex1], m_edgePairs[edgeIndex2]);
}

size_t Graph::edgeCount() const
{
  return m_edgePairs.size();
}

std::vector<size_t> Graph::neighbors(size_t index) const
{
  if (index == size()) {
    std::vector<size_t> emptyVector;
    return std::vector<size_t>(emptyVector);
  }
  assert(index < size());
  return std::vector<size_t>(m_adjacencyList[index]);
}

std::vector<size_t> Graph::edges(size_t index) const
{
  assert(index < size());
  return std::vector<size_t>(m_edgeMap[index]);
}

std::pair<size_t, size_t> Graph::endpoints(size_t index) const
{
  assert(index < edgeCount());
  return std::pair<size_t, size_t>(m_edgePairs[index]);
}

size_t Graph::degree(size_t index) const
{
  if (index >= m_adjacencyList.size())
    return 0;
  return m_adjacencyList[index].size();
}

bool Graph::containsEdge(size_t a, size_t b) const
{
  if (a >= size() || b >= size())
    return false;

  const std::vector<size_t>& neighborsA = neighbors(a);

  return std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end();
}

const Array<std::pair<size_t, size_t>>& Graph::edgePairs() const
{
  return m_edgePairs;
}

int Graph::createNewSubgraph() const
{
  // Try to find an empty subgraph to reuse
  for (size_t i = 0; i < m_subgraphToVertices.size(); i++) {
    if (m_subgraphToVertices[i].empty()) {
      m_subgraphDirty[i] = false;
      return int(i);
    }
  }
  // Otherwise, extend the list
  int r = m_subgraphDirty.size();
  m_subgraphToVertices.emplace_back();
  m_subgraphDirty.push_back(false);
  return r;
}

void Graph::checkSplitSubgraph(int subgraph) const
{
  if (!m_subgraphDirty[subgraph])
    return;
  m_subgraphDirty[subgraph] = false;
  // First, set all vertices to subgraph -1 (meaning not visited)
  for (size_t i : m_subgraphToVertices[subgraph])
    m_vertexToSubgraph[i] = -1;
  // Then, try to classify all vertices in some subgraph
  int currentSubgraph = subgraph;
  std::set<size_t> inputVertices = m_subgraphToVertices[subgraph];
  m_subgraphToVertices[subgraph] = std::set<size_t>();
  for (size_t i : inputVertices) {
    if (m_vertexToSubgraph[i] < 0) {
      if (currentSubgraph < 0)
        currentSubgraph = createNewSubgraph();
      // Walk through all connected vertices
      std::vector<size_t> verticesToVisit;
      verticesToVisit.push_back(i);
      do {
        size_t currentVertex = verticesToVisit.back();
        verticesToVisit.pop_back();
        // Assign new vertices to the current subgraph
        if (m_vertexToSubgraph[currentVertex] < 0) {
          m_vertexToSubgraph[currentVertex] = currentSubgraph;
          m_subgraphToVertices[currentSubgraph].insert(currentVertex);
          const std::vector<size_t> neighborList = neighbors(currentVertex);
          verticesToVisit.insert(verticesToVisit.end(), neighborList.begin(),
                                 neighborList.end());
        }
      } while (!verticesToVisit.empty());
      currentSubgraph = -1;
    }
  }
}

void Graph::updateSubgraphs() const
{
  for (size_t v : m_loneVertices) {
    int newSubgraph = createNewSubgraph();
    m_vertexToSubgraph[v] = newSubgraph;
    m_subgraphToVertices[newSubgraph].insert(v);
  }
  m_loneVertices.clear();
  for (size_t i = 0; i < m_subgraphToVertices.size(); i++) {
    checkSplitSubgraph(i);
  }
}

std::vector<std::set<size_t>> Graph::connectedComponents() const
{
  updateSubgraphs();
  std::vector<std::set<size_t>> r;
  for (const std::set<size_t>& s : m_subgraphToVertices) {
    if (!s.empty())
      r.push_back(s);
  }
  return r;
}

std::set<size_t> Graph::connectedComponent(size_t index) const
{
  size_t subgraphIndex = subgraph(index);
  return m_subgraphToVertices[subgraphIndex];
}

size_t Graph::subgraphsCount() const
{
  updateSubgraphs();
  size_t r = 0;
  for (const std::set<size_t>& s : m_subgraphToVertices) {
    if (!s.empty())
      r++;
  }
  return r;
}

size_t Graph::subgraph(size_t element) const
{
  int r = m_vertexToSubgraph[element];
  // Index -1 means disconnected (its own subgraph)
  if (r < 0) {
    int newSubgraph = createNewSubgraph();
    m_vertexToSubgraph[element] = newSubgraph;
    m_subgraphToVertices[newSubgraph].insert(element);
    return newSubgraph;
  }
  if (m_subgraphDirty[r]) {
    checkSplitSubgraph(r);
    r = m_vertexToSubgraph[element];
  }
  return r;
}

size_t Graph::subgraphCount(size_t element) const
{
  int subgraphIndex = subgraph(element);
  return m_subgraphToVertices[subgraphIndex].size();
}

size_t Graph::getConnectedID(size_t index) const
{
  return subgraph(index);
}
} // namespace Avogadro::Core
