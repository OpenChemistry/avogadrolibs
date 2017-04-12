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

  /** Sets the number of verticies in the graph to size @p n. */
  void setSize(size_t n);

  /** Returns the number of verticies in the graph. */
  size_t size() const;

  /** Returns \c true if the graph is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /** Removes all verticies and edges from the graph. */
  void clear();

  /** Adds a vertex to the graph and returns its index. */
  size_t addVertex();

  /** Removes the vertex at @p index from the graph. */
  void removeVertex(size_t index);

  /** Returns the number of verticies in the graph. */
  size_t vertexCount() const;

  /** Adds an edge between verticies @p a and @p b. */
  void addEdge(size_t a, size_t b);

  /** Removes the edge between veritices @p a and @p b. */
  void removeEdge(size_t a, size_t b);

  /** Removes all of the edges from the graph. */
  void removeEdges();

  /**
   * Removes all of the edges that contain the vertex at @p index from the
   * graph.
   */
  void removeEdges(size_t index);

  /** Returns the number of edges in the graph. */
  size_t edgeCount() const;

  /**
   * Returns a vector containing the indicies of each vertex that the vertex at
   * index shares an edge with.
   */
  const std::vector<size_t>& neighbors(size_t index) const;

  /** Returns the degree of the vertex at @p index. */
  size_t degree(size_t index) const;

  /**
   * Returns \c true if the graph contains an edge between verticies @p a and
   * @p b.
   */
  bool containsEdge(size_t a, size_t b) const;

  /**
   * Returns a vector of vector containing the indicies of each vertex in each
   * connected component in the graph.
   */
  std::vector<std::vector<size_t>> connectedComponents() const;

private:
  std::vector<std::vector<size_t>> m_adjacencyList;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_GRAPH_H
