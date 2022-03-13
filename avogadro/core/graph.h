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

#ifndef AVOGADRO_CORE_GRAPH_H
#define AVOGADRO_CORE_GRAPH_H

#include "avogadrocore.h"
#include "array.h"
#include "connectedgroup.h"

#include <cstddef>
#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class Graph graph.h <avogadro/core/graph.h>
 * @brief The Graph class represents a graph data structure.
 */
class AVOGADROCORE_EXPORT Graph
{
public:
  /** Creates a new, empty graph. */
  Graph();

  /** Creates a new graph containing size @p n vertices. */
  explicit Graph(size_t n);

  /** Destroys the graph. */
  ~Graph();

  /** Sets the number of vertices in the graph to size @p n. */
  void setSize(size_t n);

  /** @return the number of vertices in the graph. */
  size_t size() const;

  /** @return \c true if the graph is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /** Removes all vertices and edges from the graph. */
  void clear();

  /** Adds a vertex to the graph and returns its index. */
  size_t addVertex();

  /** Removes the vertex at @p index from the graph. */
  void removeVertex(size_t index);

  /** Swaps two vertices' indices, without affecting connectivity */
  void swapVertexIndices(size_t a, size_t b);

  /** @return the number of vertices in the graph. */
  size_t vertexCount() const;

  /** Adds an edge between vertices @p a and @p b. */
  void addEdge(size_t a, size_t b);

  /** Removes the edge between vertices @p a and @p b. */
  void removeEdge(size_t a, size_t b);

  /** Removes all of the edges from the graph. */
  void removeEdges();

  /**
   * Removes all of the edges that contain the vertex at @p index from the
   * graph.
   */
  void removeEdges(size_t index);

  /**
   * Removes the edge at @p edgeIndex, and creates a new one between vertices
   * @p a and @p b, with the same index as the removed edge.
   */
  void editEdgeInPlace(size_t edgeIndex, size_t a, size_t b);

  /** Swaps two edges' indices, without affecting connectivity */
  void swapEdgeIndices(size_t edgeIndex1, size_t edgeIndex2);

  /** @return the number of edges in the graph. */
  size_t edgeCount() const;

  /**
   * @return a vector containing the indices of each vertex that the vertex at
   * index shares an edge with.
   */
  const std::vector<size_t>& neighbors(size_t index) const;

  /**
   * @return a vector containing the indices of each edge that the vertex at
   * @p index is an endpoint of; that is, the edges incident at it.
   */
  const std::vector<size_t>& edges(size_t index) const;

  /**
   * @return the indices of the two vertices that the edge at @p index connects;
   * that is, its endpoints.
   */
  const std::pair<size_t, size_t>& endpoints(size_t edgeIndex) const;

  /** @return the degree of the vertex at @p index. */
  size_t degree(size_t index) const;

  /**
   * @return \c true if the graph contains an edge between vertices @p a and
   * @p b.
   */
  bool containsEdge(size_t a, size_t b) const;

  /**
   * @return an array with all edges, where every element contains the indices
   * of both endpoints of the edge with index equal to the element's array index.
   */
  const Array<std::pair<size_t, size_t>>& edgePairs() const;

  /**
   * @return a vector of vector containing the indices of each vertex in each
   * connected component in the graph.
   */
  std::vector<std::set<size_t>> connectedComponents() const;

  /**
   * @return a set containing the indices of each vertex connected with @p
   * index.
   */
  std::set<size_t> connectedComponent(size_t index) const;

  /** @return the number of connected subgraphs. */
  size_t subgraphsCount() const;

  /**  @return the subgraphs ID from the @p index. */
  size_t subgraph(size_t index) const;

  /**  @return the group size from the @p index. */
  size_t subgraphCount(size_t index) const;

  /**
   * Get the group ID
   */
  size_t getConnectedID(size_t index) const;

private:
  std::set<size_t> checkConectivity(size_t a, size_t b) const;
  std::vector<std::vector<size_t>> m_adjacencyList;
  std::vector<std::vector<size_t>> m_edgeMap;
  Array<std::pair<size_t, size_t>> m_edgePairs;
  ConnectedGroup m_subgraphs;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_GRAPH_H
