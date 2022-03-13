/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "graph.h"

#include <avogadro/core/connectedgroup.h>

#include <algorithm>
#include <cassert>
#include <set>
#include <stack>

namespace Avogadro {
namespace Core {

Graph::Graph() : m_subgraphs() {}

Graph::Graph(size_t n) : m_adjacencyList(n), m_subgraphs(n) {}

Graph::~Graph() {}

void Graph::setSize(size_t n)
{
  // If the graph is being made smaller we first need to remove all of the edges
  // from the soon to be removed vertices.
  for (size_t i = n; i < m_adjacencyList.size(); ++i) {
    removeEdges(i);
    m_subgraphs.removeNode(i);
  }
  if (m_adjacencyList.size() < n) {
    m_subgraphs.addNodes(n - m_adjacencyList.size());
  }

  m_adjacencyList.resize(n);
  m_edgeMap.resize(n);
}

size_t Graph::size() const
{
  return m_adjacencyList.size();
}

bool Graph::isEmpty() const
{
  return m_adjacencyList.empty();
}

void Graph::clear()
{
  m_adjacencyList.clear();
  m_edgeMap.clear();
  m_subgraphs.clear();
}

size_t Graph::addVertex()
{
  m_subgraphs.addNode(size());
  setSize(size() + 1);
  return size() - 1;
}

void Graph::removeVertex(size_t index)
{
  assert(index < size());
  m_subgraphs.removeConnection(index);
  // Remove the edges to the vertex.
  removeEdges(index);

  // Remove vertex's adjacency list.
  m_adjacencyList.erase(m_adjacencyList.begin() + index);
  m_edgeMap.erase(m_edgeMap.begin() + index);
}

void Graph::swapVertexIndices(size_t a, size_t b)
{
  // Swap all references to a and b in m_adjacencyList
  for (size_t i = 0; i < m_adjacencyList[a].size(); i++) {
    size_t otherIndex = m_adjacencyList[a][i];
    if (otherIndex == b)
      continue;
    for (size_t j = 0; j < m_adjacencyList[otherIndex].size(); j++) {
      if (m_adjacencyList[otherIndex][j] == a) {
        m_adjacencyList[otherIndex][j] = b;
        break;
      }
    }
  }
  for (size_t i = 0; i < m_adjacencyList[b].size(); i++) {
    size_t otherIndex = m_adjacencyList[b][i];
    if (otherIndex == a)
      continue;
    for (size_t j = 0; j < m_adjacencyList[otherIndex].size(); j++) {
      if (m_adjacencyList[otherIndex][j] == b) {
        m_adjacencyList[otherIndex][j] = a;
        break;
      }
    }
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

void Graph::addEdge(size_t a, size_t b)
{
  assert(a < size());
  assert(b < size());
  std::vector<size_t>& neighborsA = m_adjacencyList[a];
  std::vector<size_t>& neighborsB = m_adjacencyList[b];

  // Ensure edge does not exist already.
  if (std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end())
    return;

  m_subgraphs.addConnection(a, b);

  // Add the edge to each vertex' adjacency list.
  neighborsA.push_back(b);
  neighborsB.push_back(a);

  // Add the edge to each vertex' incident edge list.
  size_t newEdgeIndex = edgeCount();
  m_edgeMap[a].push_back(newEdgeIndex);
  m_edgeMap[b].push_back(newEdgeIndex);

  m_edgePairs.push_back(std::pair<size_t, size_t>(a, b));
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

  if (iter != neighborsA.end()) {
    neighborsA.erase(iter);
    neighborsB.erase(std::find(neighborsB.begin(), neighborsB.end(), a));
  }

  size_t index;
  for (size_t i = 0; i < m_edgeMap[a].size(); i++) {
    index = m_edgeMap[a][i];
    const std::pair<size_t, size_t> &pair = m_edgePairs[index];
    if (pair.first == b || pair.second == b) {
      m_edgeMap[a].erase(m_edgeMap[a].begin() + i);
      break;
    }
  }

  for (size_t i = 0; i < m_edgeMap[b].size(); i++) {
    if (m_edgeMap[b][i] == index) {
      m_edgeMap[b].erase(m_edgeMap[b].begin() + i);
      break;
    }
  }

  m_edgePairs.erase(m_edgePairs.begin() + index);

  if (m_subgraphs.getGroup(a) == m_subgraphs.getGroup(b)) {
    std::set<size_t> connected = checkConectivity(a, b);
    if (!connected.empty()) {
      m_subgraphs.removeConnection(a, b, connected);
    }
  }
}

void Graph::removeEdges()
{
  m_subgraphs.removeConnections();
  for (size_t i = 0; i < m_adjacencyList.size(); ++i)
    m_adjacencyList[i].clear();
}

void Graph::removeEdges(size_t index)
{
  m_subgraphs.removeConnection(index);
  const std::vector<size_t>& nbrs = m_adjacencyList[index];

  for (size_t i = 0; i < nbrs.size(); ++i) {
    std::vector<size_t>& neighborsList = m_adjacencyList[nbrs[i]];

    // Remove vertex from its neighbors' adjacency list.
    neighborsList.erase(
      std::find(neighborsList.begin(), neighborsList.end(), index));
  }
}

void Graph::editEdgeInPlace(size_t edgeIndex, size_t a, size_t b)
{
  auto &pair = m_edgePairs[edgeIndex];

  // Remove references to the deleted edge from both endpoints.
  for(size_t i = 0; i < m_edgeMap[pair.first].size(); i++) {
    std::swap(m_edgeMap[pair.first][i], m_edgeMap[pair.first].back());
    m_edgeMap[pair.first].pop_back();
  }
  for(size_t i = 0; i < m_edgeMap[pair.second].size(); i++) {
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
  const std::pair<size_t, size_t> &pair1 = m_edgePairs[edgeIndex1];
  std::array<size_t *, 2> changeTo2;
  for (size_t i = 0; i < m_edgeMap[pair1.first].size(); i++) {
    if (m_edgeMap[pair1.first][i] == edgeIndex1) {
      changeTo2[0] = &m_edgeMap[pair1.first][i];
    }
  }
  for (size_t i = 0; i < m_edgeMap[pair1.second].size(); i++) {
    if (m_edgeMap[pair1.second][i] == edgeIndex1) {
      changeTo2[0] = &m_edgeMap[pair1.second][i];
    }
  }
  const std::pair<size_t, size_t> &pair2 = m_edgePairs[edgeIndex2];
  std::array<size_t *, 2> changeTo1;
  for (size_t i = 0; i < m_edgeMap[pair2.first].size(); i++) {
    if (m_edgeMap[pair2.first][i] == edgeIndex2) {
      changeTo1[0] = &m_edgeMap[pair2.first][i];
    }
  }
  for (size_t i = 0; i < m_edgeMap[pair2.second].size(); i++) {
    if (m_edgeMap[pair2.second][i] == edgeIndex2) {
      changeTo1[0] = &m_edgeMap[pair2.second][i];
    }
  }

  /*
  Swap m_edgeMap values only after reading everything, to avoid race condition.
  */
  *changeTo2[0] = edgeIndex2;
  *changeTo2[0] = edgeIndex2;
  *changeTo1[0] = edgeIndex1;
  *changeTo1[0] = edgeIndex1;

  std::swap(m_edgePairs[edgeIndex1], m_edgePairs[edgeIndex2]);
}

size_t Graph::edgeCount() const
{
  return m_edgePairs.size();
}

const std::vector<size_t>& Graph::neighbors(size_t index) const
{
  assert(index < size());
  return m_adjacencyList[index];
}

const std::vector<size_t>& Graph::edges(size_t index) const
{
  assert(index < size());
  return m_edgeMap[index];
}

const std::pair<size_t, size_t>& Graph::endpoints(size_t index) const
{
  assert(index < edgeCount());
  return m_edgePairs[index];
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

std::vector<std::set<size_t>> Graph::connectedComponents() const
{
  return m_subgraphs.getAllGroups();
}

std::set<size_t> Graph::connectedComponent(size_t index) const
{
  size_t group = m_subgraphs.getGroup(index);
  return m_subgraphs.getNodes(group);
}

size_t Graph::subgraphsCount() const
{
  return m_subgraphs.groupCount();
}

size_t Graph::subgraph(size_t element) const
{
  return m_subgraphs.getGroup(element);
}

size_t Graph::subgraphCount(size_t element) const
{
  return m_subgraphs.getGroupSize(element);
}

size_t Graph::getConnectedID(size_t index) const
{
  return m_subgraphs.getGroup(index);
}
} // namespace Core
} // namespace Avogadro
