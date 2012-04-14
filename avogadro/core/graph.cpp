/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "graph.h"

#include <algorithm>
#include <cassert>

namespace MolCore {

// === Graph =============================================================== //
/// \class Graph
/// \brief The Graph class represents a graph data structure.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new, empty graph.
Graph::Graph()
{
}

/// Creates a new graph containing size \p n verticies.
Graph::Graph(size_t n)
  : m_adjacencyList(n)
{
}

/// Destroys the graph.
Graph::~Graph()
{
}

// --- Properties ---------------------------------------------------------- //
/// Sets the number of verticies in the graph to size \p n.
void Graph::setSize(size_t n)
{
  // if the graph is being made smaller we first need to remove
  // all of the edges from the soon to be removed verticies
  for (size_t i = n; i < m_adjacencyList.size(); i++) {
    removeEdges(i);
  }

  m_adjacencyList.resize(n);
}

/// Returns the number of verticies in the graph.
size_t Graph::size() const
{
  return m_adjacencyList.size();
}

/// Returns \c true if the graph is empty (i.e. size() == \c 0).
bool Graph::isEmpty() const
{
  return m_adjacencyList.empty();
}

/// Removes all verticies and edges from the graph.
void Graph::clear()
{
  setSize(0);
}

// --- Structure ----------------------------------------------------------- //
/// Adds a vertex to the graph and returns its index.
size_t Graph::addVertex()
{
  setSize(size() + 1);

  return size() - 1;
}

/// Removes the vertex at \p index from the graph.
void Graph::removeVertex(size_t index)
{
  assert(index < size());

  // remove the edges to the vertex
  removeEdges(index);

  // remove vertex's adjacency list
  m_adjacencyList.erase(m_adjacencyList.begin() + index);
}

/// Returns the number of verticies in the graph.
size_t Graph::vertexCount() const
{
  return m_adjacencyList.size();
}

/// Adds an edge between verticies \p a and \p b.
void Graph::addEdge(size_t a, size_t b)
{
  assert(a < size());
  assert(b < size());

  std::vector<size_t> &neighborsA = m_adjacencyList[a];
  std::vector<size_t> &neighborsB = m_adjacencyList[b];

  // ensure edge does not exist already
  if (std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end())
    return;

  // add the edge to each verticies adjacency list
  neighborsA.push_back(b);
  neighborsB.push_back(a);
}

/// Removes the edge between veritices \p a and \p b.
void Graph::removeEdge(size_t a, size_t b)
{
  assert(a < size());
  assert(b < size());

  std::vector<size_t> &neighborsA = m_adjacencyList[a];
  std::vector<size_t> &neighborsB = m_adjacencyList[b];

  std::vector<size_t>::iterator iter = std::find(neighborsA.begin(),
                                                 neighborsA.end(),
                                                 b);

  if (iter != neighborsA.end()) {
    neighborsA.erase(iter);
    neighborsB.erase(std::find(neighborsB.begin(), neighborsB.end(), a));
  }
}

/// Removes all of the edges from the graph.
void Graph::removeEdges()
{
  for (size_t i = 0; i < m_adjacencyList.size(); ++i)
    m_adjacencyList[i].clear();
}

/// Removes all of the edges that contain the vertex at \p index
/// from the graph.
void Graph::removeEdges(size_t index)
{
  const std::vector<size_t> &nbrs = m_adjacencyList[index];

  for (size_t i = 0; i < nbrs.size(); ++i) {
    std::vector<size_t> &neighborsList = m_adjacencyList[nbrs[i]];

    // remove vertex from its neighbors' adjacency list
    neighborsList.erase(std::find(neighborsList.begin(),
                                  neighborsList.end(),
                                  index));
  }
}

/// Returns the number of edges in the graph.
size_t Graph::edgeCount() const
{
  size_t count = 0;

  for(size_t i = 0; i < size(); ++i)
    count += neighbors(i).size();

  return count / 2;
}

/// Returns a vector containing the indicies of each vertex that the
/// vertex at index shares an edge with.
const std::vector<size_t>& Graph::neighbors(size_t index) const
{
  assert(index < size());

  return m_adjacencyList[index];
}

/// Returns the degree of the vertex at \p index.
size_t Graph::degree(size_t index) const
{
  return neighbors(index).size();
}

/// Returns \c true if the graph contains an edge between verticies
/// \p a and \p b.
bool Graph::containsEdge(size_t a, size_t b) const
{
  assert(a < size());
  assert(b < size());

  const std::vector<size_t> &neighborsA = neighbors(a);

  return std::find(neighborsA.begin(), neighborsA.end(), b) != neighborsA.end();
}

// --- Algorithms ---------------------------------------------------------- //
/// Returns a vector of vector containing the indicies of each vertex
/// in each connected component in the graph.
std::vector<std::vector<size_t> > Graph::connectedComponents() const
{
  std::vector<std::vector<size_t> > components;

  // position of next vertex to root the depth-first search
  size_t position = 0;

  // bitset containing each vertex that has been visitited
  std::vector<bool> visited(size());

  for (;;) {
    std::vector<size_t> component(size());

    std::vector<size_t> row;
    row.push_back(position);

    while (!row.empty()) {
      std::vector<size_t> nextRow;

      for (size_t i = 0; i < row.size(); i++) {
        size_t vertex = row[i];

        // add vertex to the component
        component.push_back(vertex);

        // mark vertex as visited
        visited[vertex] = true;

        // iterate through each neighbor
        const std::vector<size_t> &nbrs = m_adjacencyList[vertex];
        for (size_t j = 0; j < nbrs.size(); ++j) {
          if (visited[nbrs[j]] == false) {
            nextRow.push_back(nbrs[j]);
          }
        }
      }

      row = nextRow;
    }

    // add component to list of components
    components.push_back(component);

    // find next unvisited vertex
    bool done = true;
    for (size_t i = position + 1; i < size(); ++i) {
      if(visited[i] == false){
        position = i;
        done = false;
        break;
      }
    }

    if (done)
      break;
  }

  return components;
}

} // end MolCore namespace
