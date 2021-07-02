/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "moleculegraph.h"

#include <cassert>
#include <iostream>

namespace Avogadro {
namespace Core {
namespace {
// Make an std::pair where the lower index is always first in the pair. This
// offers us the guarantee that any given pair of atoms will always result in
// a pair that is the same no matter what the order of the atoms given.
std::pair<Index, Index> makeBondPair(const Index& a, const Index& b)
{
  return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
}
} // namespace

MoleculeGraph::MoleculeGraph() : m_graphDirty(false) {}
MoleculeGraph::MoleculeGraph(const MoleculeGraph& other)
  : m_graph(other.m_graph), m_graphDirty(other.m_graphDirty),
    m_bondPairs(other.m_bondPairs), m_bondOrders(other.m_bondOrders),
    m_atomicNumbers(other.m_atomicNumbers)
{}

MoleculeGraph::MoleculeGraph(MoleculeGraph&& other) noexcept
  : m_graph(std::move(other.m_graph)),
    m_graphDirty(std::move(other.m_graphDirty)),
    m_bondPairs(std::move(other.m_bondPairs)),
    m_bondOrders(std::move(other.m_bondOrders)),
    m_atomicNumbers(std::move(other.m_atomicNumbers))

{}
MoleculeGraph MoleculeGraph::operator=(const MoleculeGraph& other)
{
  if (this != &other) {
    m_graph = other.m_graph;
    m_graphDirty = other.m_graphDirty;
    m_bondPairs = other.m_bondPairs;
    m_bondOrders = other.m_bondOrders;
    m_atomicNumbers = other.m_atomicNumbers;
  }
  return *this;
}
MoleculeGraph MoleculeGraph::operator=(MoleculeGraph&& other) noexcept
{
  if (this != &other) {
    m_graph = std::move(other.m_graph);
    m_graphDirty = std::move(other.m_graphDirty);
    m_bondPairs = std::move(other.m_bondPairs);
    m_bondOrders = std::move(other.m_bondOrders);
    m_atomicNumbers = std::move(other.m_atomicNumbers);
  }
  return *this;
}

MoleculeGraph::~MoleculeGraph() {}

Index MoleculeGraph::bondCount() const
{
  assert(m_bondPairs.size() == m_bondOrders.size());
  return m_bondPairs.size();
}

Array<std::pair<Index, Index>>& MoleculeGraph::bondPairs()
{
  return m_bondPairs;
}
const Array<std::pair<Index, Index>>& MoleculeGraph::bondPairs() const
{
  return m_bondPairs;
}

Array<unsigned char>& MoleculeGraph::bondOrders()
{
  return m_bondOrders;
}
const Array<unsigned char>& MoleculeGraph::bondOrders() const
{
  return m_bondOrders;
}

Graph& MoleculeGraph::graph()
{
  updateGraph();
  return m_graph;
}

const Graph& MoleculeGraph::graph() const
{
  updateGraph();
  return m_graph;
}

Array<unsigned char>& MoleculeGraph::atomicNumbers()
{
  return m_atomicNumbers;
}

const Array<unsigned char>& MoleculeGraph::atomicNumbers() const
{
  return m_atomicNumbers;
}

std::pair<Index, Index> MoleculeGraph::bondPair(Index bondId) const
{
  return bondId < bondCount() ? m_bondPairs[bondId]
                              : std::make_pair(MaxIndex, MaxIndex);
}

bool MoleculeGraph::setBondPairs(const Array<std::pair<Index, Index>>& pairs)
{
  if (pairs.size() == bondCount()) {
    Index bond = 0;
    for (const auto& pair : pairs) {
      setBondPair(bond, pair);
      ++bond;
    }
    return true;
  }
  return false;
}

bool MoleculeGraph::setBondPair(Index bondId,
                                const std::pair<Index, Index>& pair)
{
  if (bondId < bondCount()) {
    updateGraph();
    m_graph.removeEdge(m_bondPairs[bondId].first, m_bondPairs[bondId].second);
    m_bondPairs[bondId] = pair;
    m_graph.removeEdge(pair.first, pair.second);
    return true;
  }
  return false;
}

unsigned char MoleculeGraph::bondOrder(Index bondId) const
{
  return bondId < m_bondOrders.size() ? m_bondOrders[bondId] : 0;
}

bool MoleculeGraph::setBondOrders(const Array<unsigned char>& orders)
{
  if (orders.size() == bondCount()) {
    m_bondOrders = orders;
    return true;
  }
  return false;
}

bool MoleculeGraph::setBondOrder(Index bondId, unsigned char order)
{
  if (bondId < bondCount()) {
    m_bondOrders[bondId] = order;
    return true;
  }
  return false;
}

Index MoleculeGraph::atomCount() const
{
  return static_cast<Index>(m_atomicNumbers.size());
}

Index MoleculeGraph::atomCount(unsigned char number) const
{
  Index count(0);
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin();
       it != m_atomicNumbers.end(); ++it) {
    if (*it == number)
      ++count;
  }
  return count;
}

unsigned char MoleculeGraph::atomicNumber(Index atomId) const
{
  return atomId < m_atomicNumbers.size() ? m_atomicNumbers[atomId]
                                         : InvalidElement;
}

bool MoleculeGraph::setAtomicNumbers(const Core::Array<unsigned char>& nums)
{
  if (nums.size() == atomCount()) {
    m_atomicNumbers = nums;
    return true;
  }
  return false;
}

bool MoleculeGraph::setAtomicNumber(Index atomId, unsigned char number)
{
  if (atomId < atomCount()) {
    m_atomicNumbers[atomId] = number;
    return true;
  }
  return false;
}

bool MoleculeGraph::hasCustomElements() const
{
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
                                            itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    if (Core::isCustomElement(*it))
      return true;
  }
  return false;
}

std::map<unsigned char, size_t> MoleculeGraph::composition() const
{
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = m_atomicNumbers.begin(),
                                            itEnd = m_atomicNumbers.end();
       it != itEnd; ++it) {
    ++composition[*it];
  }
  return composition;
}

Index MoleculeGraph::findBond(Index atomId1, Index atomId2) const
{
  assert(atomId1 < atomCount());
  assert(atomId2 < atomCount());

  std::pair<Index, Index> pair = makeBondPair(atomId1, atomId2);
  Array<std::pair<Index, Index>>::const_iterator iter =
    std::find(m_bondPairs.begin(), m_bondPairs.end(), pair);

  Index index = static_cast<Index>(std::distance(m_bondPairs.begin(), iter));
  return index;
}

void MoleculeGraph::setGraphDirty(bool dirty) const
{
  m_graphDirty = dirty;
}

//// protected and private

bool MoleculeGraph::addAtom(unsigned char number)
{
  m_atomicNumbers.push_back(number);
  updateGraph();
  m_graph.addVertex();
  return true;
}

bool MoleculeGraph::addBond(Index atom1, Index atom2, unsigned char order)
{
  assert(atom1 < m_atomicNumbers.size());
  assert(atom2 < m_atomicNumbers.size());
  Index index = findBond(atom1, atom2);
  if (index == bondCount()) {
    m_bondPairs.push_back(makeBondPair(atom1, atom2));
    m_bondOrders.push_back(order);
    updateGraph();
    m_graph.addEdge(atom1, atom2);
    return true;
  } else {
    m_bondOrders[index] = order;
    return false;
  }
}

bool MoleculeGraph::removeAtom(Index index)
{
  if (index >= atomCount())
    return false;
  updateGraph();
  m_graph.removeVertex(index);
  m_atomicNumbers.swapAndPop(index);
  removeBonds(index);
  // the bonds from back() now are in index, so we need to rebond it
  rebondBond(m_atomicNumbers.size() - 1, index);
  return true;
}

bool MoleculeGraph::removeBonds(Index atom)
{
  if (atom >= bondCount())
    return false;
  Index i = 0;
  while (i < m_bondPairs.size()) {
    auto& bond = m_bondPairs[i];
    if (bond.first == atom || bond.second == atom) {
      removeBond(i);
    } else {
      ++i;
    }
  }
  return true;
}

bool MoleculeGraph::removeBond(Index index)
{
  if (index >= bondCount())
    return false;
  updateGraph();
  m_graph.removeEdge(m_bondPairs[index].first, m_bondPairs[index].second);
  Index newSize = static_cast<Index>(m_bondOrders.size() - 1);
  m_bondOrders.swapAndPop(index);
  m_bondPairs.swapAndPop(index);
  return true;
}

void MoleculeGraph::clearAtoms()
{
  m_atomicNumbers.clear();
  m_bondOrders.clear();
  m_bondPairs.clear();
  m_graph.clear();
  m_graphDirty = false;
}

void MoleculeGraph::clearBonds()
{
  m_bondOrders.clear();
  m_bondPairs.clear();
  m_graph.removeEdges();
  m_graph.setSize(atomCount());
  m_graphDirty = false;
}

void MoleculeGraph::updateGraph() const
{
  if (!m_graphDirty)
    return;
  m_graphDirty = false;
  m_graph.clear();
  m_graph.setSize(atomCount());
  typedef Array<std::pair<Index, Index>>::const_iterator IterType;
  for (IterType it = m_bondPairs.begin(); it != m_bondPairs.end(); ++it) {
    m_graph.addEdge(it->first, it->second);
  }
}

void MoleculeGraph::rebondBond(Index newIndex, Index oldIndex)
{
  // nothing to do
  if (newIndex == oldIndex)
    return;
  for (auto& pair : m_bondPairs) {
    if (pair.first == oldIndex) {
      pair.first = newIndex;
    } else if (pair.second == oldIndex) {
      pair.second = newIndex;
    }
  }
  m_graphDirty = true;
}

} // namespace Core
} // namespace Avogadro
