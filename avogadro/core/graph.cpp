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

  // Add the edge to each verticies adjacency list.
  neighborsA.push_back(b);
  neighborsB.push_back(a);
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

size_t Graph::edgeCount() const
{
  size_t count = 0;

  for (size_t i = 0; i < size(); ++i)
    count += neighbors(i).size();

  return count / 2;
}

const std::vector<size_t>& Graph::neighbors(size_t index) const
{
  assert(index < size());
  return m_adjacencyList[index];
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
