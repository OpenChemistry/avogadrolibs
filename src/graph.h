#ifndef MOLCORE_GRAPH_H
#define MOLCORE_GRAPH_H

#include "molcore.h"

#include <vector>
#include <cstddef>

namespace MolCore {

class MOLCORE_EXPORT Graph
{
public:
  // construction and destruction
  Graph();
  Graph(size_t size);
  ~Graph();

  // properties
  void setSize(size_t size);
  size_t size() const;
  bool isEmpty() const;
  void clear();

  // structure
  size_t addVertex();
  void removeVertex(size_t index);
  size_t vertexCount() const;
  void addEdge(size_t a, size_t b);
  void removeEdge(size_t a, size_t b);
  void removeEdges();
  void removeEdges(size_t index);
  size_t edgeCount() const;
  const std::vector<size_t>& neighbors(size_t index) const;
  size_t degree(size_t index) const;
  bool containsEdge(size_t a, size_t b) const;

private:
  std::vector<std::vector<size_t> > m_adjacencyList;
};

} // end MolCore namespace

#endif // MOLCORE_GRAPH_H
