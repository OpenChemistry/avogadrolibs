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

#include <vector>
#include <cstddef>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT Graph
{
public:
  // construction and destruction
  Graph();
  Graph(size_t n);
  ~Graph();

  // properties
  void setSize(size_t n);
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

  // algorithms
  std::vector<std::vector<size_t> > connectedComponents() const;

private:
  std::vector<std::vector<size_t> > m_adjacencyList;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_GRAPH_H
