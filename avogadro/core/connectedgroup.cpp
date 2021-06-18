/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "connectedgroup.h"

#include <algorithm>
#include <cassert>

void checkRemove(std::vector<std::set<size_t>>& vector)
{
  while (vector[vector.size() - 1].size() == 0) {
    vector.pop_back();
  }
}

namespace Avogadro {
namespace Core {

ConnectedGroup::ConnectedGroup() {}

ConnectedGroup::ConnectedGroup(size_t n) : m_groupToElement(n)
{
  resetToSize(n);
}

ConnectedGroup::~ConnectedGroup() {}

void ConnectedGroup::addElement(size_t index)
{
  m_elementToGroup[index] = m_groupToElement.size();
  std::set<size_t> group;
  group.insert(index);
  m_groupToElement.push_back(group);
}

void ConnectedGroup::addElements(size_t n)
{
  size_t offset = m_elementToGroup.size();
  for (size_t i = 0; i < n; ++i) {
    addElement(i + offset);
  }
}

void ConnectedGroup::addConnection(size_t a, size_t b)
{
  assert(m_elementToGroup.find(a) != m_elementToGroup.end());
  assert(m_elementToGroup.find(b) != m_elementToGroup.end());

  size_t group_a = m_elementToGroup[a];
  size_t group_b = m_elementToGroup[b];
  if (group_a != group_b) {
    for (size_t element : m_groupToElement[group_b]) {
      m_elementToGroup[element] = group_a;
      m_groupToElement[group_a].insert(element);
    }
    m_groupToElement[group_b].clear();
    checkRemove(m_groupToElement);
  }
}

void ConnectedGroup::removeElement(size_t index)
{
  assert(m_elementToGroup.find(index) != m_elementToGroup.end());
  removeConnection(index);
  size_t group = m_elementToGroup[index];
  m_elementToGroup.erase(group);
}

void ConnectedGroup::removeConnections()
{
  size_t n = m_elementToGroup.size();
  clear();
  resetToSize(n);
}

void ConnectedGroup::removeConnection(size_t index)
{
  assert(m_elementToGroup.find(index) != m_elementToGroup.end());
  size_t group = m_elementToGroup[index];
  if (m_groupToElement[group].size() > 1) {
    m_groupToElement[group].erase(index);
    checkRemove(m_groupToElement);
    addElement(index);
  }
}

// check if the group has more than 1 element (the removed one)
bool checkConectivity(const std::set<size_t>& group,
                      std::vector<size_t>& neighbors)
{
  std::sort(neighbors.begin(), neighbors.end());
  std::vector<size_t> intersection;
  std::set_intersection(neighbors.begin(), neighbors.end(), group.begin(),
                        group.end(), std::back_inserter(intersection));
  return intersection.size() > 1;
}

void ConnectedGroup::removeConnection(size_t a, std::vector<size_t> a_neighbors,
                                      size_t b, std::vector<size_t> b_neighbors)
{
  assert(m_elementToGroup.find(a) != m_elementToGroup.end());
  assert(m_elementToGroup.find(b) != m_elementToGroup.end());
  assert(m_elementToGroup[a] == m_elementToGroup[b]);

  bool stillCOnected = false;
  if (a_neighbors.size() < b_neighbors.size()) {
    stillCOnected =
      checkConectivity(m_groupToElement[m_elementToGroup[a]], b_neighbors);
  } else {
    stillCOnected =
      checkConectivity(m_groupToElement[m_elementToGroup[b]], a_neighbors);
  }

  if (!stillCOnected) {
    removeConnection(a);
    size_t group = m_elementToGroup[a];
    for (const auto& n : a_neighbors) {
      size_t oldGroup = m_elementToGroup[n];
      m_groupToElement[oldGroup].erase(n);
      checkRemove(m_groupToElement);
      m_groupToElement[group].insert(n);
      m_elementToGroup[n] = group;
    }
  }
}

void ConnectedGroup::clear()
{
  m_elementToGroup.clear();
  m_groupToElement.clear();
}

size_t ConnectedGroup::getGroup(size_t element) const
{
  assert(m_elementToGroup.find(element) != m_elementToGroup.end());
  return m_elementToGroup.at(element);
}

std::set<size_t> ConnectedGroup::getElements(size_t group) const
{
  assert(group < m_groupToElement.size());
  return m_groupToElement[group];
}

std::vector<std::set<size_t>> ConnectedGroup::getAllGroups() const
{
  return m_groupToElement;
}

void ConnectedGroup::resetToSize(size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    m_elementToGroup[i] = i;
    m_groupToElement[i].insert(i);
  }
}

} // namespace Core
} // namespace Avogadro
