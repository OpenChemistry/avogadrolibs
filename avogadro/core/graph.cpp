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

namespace Avogadro::Core {

Graph::Graph() {}

Graph::Graph(size_t n)
  : m_adjacencyList(n), m_edgeMap(n), m_edgePairs(), m_vertexToSubgraph(n),
    m_subgraphToVertices(), m_subgraphDirty()
{
  for (size_t i = 0; i < n; i++) {
    m_vertexToSubgraph[i] = -1;
    m_loneVertices.insert(i);
  }
}

Graph::~Graph() {}

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
  assert(index < size());
  // Mark the subgraph as dirty, leave the work for later
  if (m_vertexToSubgraph[index] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[index]] = true;
  // Remove the edges to the vertex.
  removeEdges(index);

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
      m_vertexToSubgraph[i] = subgraphA;
    }
    // Just leave it empty, it could be reused
    m_subgraphToVertices[subgraphB].clear();
  }

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
  assert(a < size());
  assert(b < size());

  std::vector<size_t>& neighborsA = m_adjacencyList[a];
  std::vector<size_t>& neighborsB = m_adjacencyList[b];

  std::vector<size_t>::iterator iter =
    std::find(neighborsA.begin(), neighborsA.end(), b);

  if (iter == neighborsA.end())
    return;

  std::swap(*iter, neighborsA.back());
  neighborsA.pop_back();
  std::swap(*std::find(neighborsB.begin(), neighborsB.end(), a),
            neighborsB.back());
  neighborsB.pop_back();

  size_t edgeIndex;
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
    std::vector<size_t>& edgeList1 = m_edgeMap[m_edgePairs[edgeIndex].first];
    *std::find(edgeList1.begin(), edgeList1.end(), affectedIndex) = edgeIndex;
    std::vector<size_t>& edgeList2 = m_edgeMap[m_edgePairs[edgeIndex].second];
    *std::find(edgeList2.begin(), edgeList2.end(), affectedIndex) = edgeIndex;
  }

  // Mark the subgraph as dirty, leave the work for later
  if (m_vertexToSubgraph[a] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[a]] = true;
}

void Graph::removeEdge(size_t edgeIndex)
{
  assert(edgeIndex < edgeCount());
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
  m_vertexToSubgraph[index] = -1;
  m_loneVertices.insert(index);
  // Mark the subgraph as dirty, leave the work for later
  if (m_vertexToSubgraph[index] >= 0)
    m_subgraphDirty[m_vertexToSubgraph[index]] = true;

  const std::vector<size_t>& edges = m_edgeMap[index];
  for (size_t i = 0; i < edges.size(); ++i)
    removeEdge(edges[i]);
}

void Graph::editEdgeInPlace(size_t edgeIndex, size_t a, size_t b)
{
  auto& pair = m_edgePairs[edgeIndex];

  // Remove references to the deleted edge from both endpoints.
  for (size_t i = 0; i < m_edgeMap[pair.first].size(); i++) {
    std::swap(m_edgeMap[pair.first][i], m_edgeMap[pair.first].back());
    m_edgeMap[pair.first].pop_back();
  }
  for (size_t i = 0; i < m_edgeMap[pair.second].size(); i++) {
    std::swap(m_edgeMap[pair.second][i], m_edgeMap[pair.second].back());
    m_edgeMap[pair.second].pop_back();
  }

  m_edgeMap[a].push_back(edgeIndex);
  m_edgeMap[b].push_back(edgeIndex);

  pair.first = a;
  pair.second = b;
}

void Graph::swapEdgeIndices(size_t edgeIndex1, size_t edgeIndex2)
{
  // Find the 4 endpoints of both edges.
  const std::pair<size_t, size_t>& pair1 = m_edgePairs[edgeIndex1];
  std::array<size_t*, 2> changeTo2;
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
  std::array<size_t*, 2> changeTo1;
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
  *changeTo2[0] = edgeIndex2;
  *changeTo2[1] = edgeIndex2;
  *changeTo1[0] = edgeIndex1;
  *changeTo1[1] = edgeIndex1;

  std::swap(m_edgePairs[edgeIndex1], m_edgePairs[edgeIndex2]);
}

size_t Graph::edgeCount() const
{
  return m_edgePairs.size();
}

std::vector<size_t> Graph::neighbors(size_t index) const
{
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
  return neighbors(index).size();
}

bool Graph::containsEdge(size_t a, size_t b) const
{
  assert(a < size());
  assert(b < size());

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
    if (!m_subgraphToVertices[i].size()) {
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
      } while (verticesToVisit.size());
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
  for (int i = 0; i < m_subgraphToVertices.size(); i++) {
    checkSplitSubgraph(i);
  }
}

std::vector<std::set<size_t>> Graph::connectedComponents() const
{
  updateSubgraphs();
  std::vector<std::set<size_t>> r;
  for (std::set<size_t> s : m_subgraphToVertices) {
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
  for (std::set<size_t> s : m_subgraphToVertices) {
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
    r = m_subgraphToVertices.size();
    m_subgraphToVertices.push_back(std::set<size_t>());
    m_subgraphToVertices[r].insert(element);
    m_subgraphDirty[r] = false;
    return r;
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
