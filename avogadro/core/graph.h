/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_GRAPH_H
#define AVOGADRO_CORE_GRAPH_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"
#include "array.h"

#include <cstddef>
#include <set>
#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class Graph graph.h <avogadro/core/graph.h>
 * @brief The Graph class represents a graph data structure.
 *
 * A graph consists of vertices and edges, wherein every edge connects two
 * vertices. Each vertex is assigned an index, starting from 0 up to size() - 1.
 * Each edge is also assigned an index, from 0 to edgeCount() - 1.
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

  /**
   * Sets the number of vertices in the graph to size @p n.
   *
   * If @p n is smaller than \c size(), this removes all vertices with index
   * @p n or higher, as well as any edges connected to them, while preserving
   * all other vertices and edges. These vertices keep their existing indices,
   * while no guarantee is made regarding preserved edge indices.
   *
   * If @p n is larger than \c size(), a number of unconnected vertices are
   * added, up to the requested size. All existing vertices and edges are
   * preserved in their current form.
   */
  void setSize(size_t n);

  /** @return the number of vertices in the graph. */
  size_t size() const;

  /** @return \c true if the graph is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /** Removes all vertices and edges from the graph. */
  void clear();

  /**
   * Adds a vertex to the graph and returns its index.
   * The new vertex is initially not connected. All existing vertices and edges
   * are preserved and their indices unchanged.
   */
  size_t addVertex();

  /**
   * Removes the vertex at @p index from the graph, as well as all edges to it.
   * If @p index is not the highest vertex index in the graph, the vertex with
   * highest index will be assigned the index of the removed vertex. All other
   * vertices will keep their indices. No guarantees are made regarding edge
   * indices.
   */
  void removeVertex(size_t index);

  /**
   * Swaps two vertices' indices, without affecting connectivity.
   * All other vertices and all edges keep their existing indices.
   */
  void swapVertexIndices(size_t a, size_t b);

  /** @return the number of vertices in the graph. */
  size_t vertexCount() const;

  /**
   * Adds an edge between vertices @p a and @p b and returns its index.
   * All existing vertices and edges are preserved unchanged.
   */
  size_t addEdge(size_t a, size_t b);

  /**
   * Removes the edge between vertices @p a and @p b.
   * All vertices keep their indices. If the removed edge has an index lower
   * than the highest edge index in the graph, the edge with the highest index
   * is given the index of the removed edge. All other edges remain unchanged.
   */
  void removeEdge(size_t a, size_t b);

  /**
   * Removes edge with index @p edgeIndex.
   * All vertices keep their indices. If @p edgeIndex is lower than the highest
   * edge index in the graph, the edge with the highest index is given the index
   * of the removed edge. All other edges remain unchanged.
   */
  void removeEdge(size_t edgeIndex);

  /** Removes all of the edges from the graph, without affecting vertices. */
  void removeEdges();

  /**
   * Removes all of the edges that contain the vertex at @p index from the
   * graph.
   */
  void removeEdges(size_t index);

  /**
   * Removes the edge at @p edgeIndex, and creates a new one between vertices
   * @p a and @p b, with the same index as the removed edge. All other edges and
   * vertices keep their current indices.
   */
  void editEdgeInPlace(size_t edgeIndex, size_t a, size_t b);

  /**
   * Swaps two edges' indices, without affecting connectivity.
   * All other edges and all vertices keep their current indices.
   */
  void swapEdgeIndices(size_t edgeIndex1, size_t edgeIndex2);

  /** @return the number of edges in the graph. */
  size_t edgeCount() const;

  /**
   * @return a vector containing the indices of each vertex that the vertex at
   * index shares an edge with.
   */
  std::vector<size_t> neighbors(size_t index) const;

  /**
   * @return a vector containing the indices of each edge that the vertex at
   * @p index is an endpoint of; that is, the edges incident at it.
   */
  std::vector<size_t> edges(size_t index) const;

  /**
   * @return the indices of the two vertices that the edge at @p index connects;
   * that is, its endpoints.
   */
  std::pair<size_t, size_t> endpoints(size_t edgeIndex) const;

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

  /** @return the subgraph ID of the connected subgraph @p index lies in. */
  size_t subgraph(size_t index) const;

  /**
   * @return the size of the connected subgraph that includes @p index,
   * that is, the number of connected vertices in it.
   */
  size_t subgraphCount(size_t index) const;

  /**
   * @return the subgraph ID of the connected subgraph @p index lies in.
   */
  size_t getConnectedID(size_t index) const;

private:
  std::set<size_t> checkConectivity(size_t a, size_t b) const;
  std::vector<std::vector<size_t>> m_adjacencyList;
  std::vector<std::vector<size_t>> m_edgeMap;
  Array<std::pair<size_t, size_t>> m_edgePairs;
  
  /** @return the (new or reused) index of a newly created empty subgraph. */
  int createNewSubgraph() const;

  /**
   * If @p subgraph is marked as dirty, traverse it
   * to check if it has split into many new subgraphs,
   * and mark the resulting subgraph(s) as clean.
   */
  void checkSplitSubgraph(int subgraph) const;

  /**
   * Traverse and mark clean all dirty subgraphs,
   * and create new subgraphs for all lone vertices.
   * All subgraph data becomes synchronized as a result.
   */
  void updateSubgraphs() const;

  mutable std::vector<int> m_vertexToSubgraph;
  mutable std::vector<std::set<size_t>> m_subgraphToVertices;
  mutable std::vector<bool> m_subgraphDirty;
  mutable std::set<size_t> m_loneVertices;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_GRAPH_H
