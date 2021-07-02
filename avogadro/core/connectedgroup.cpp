/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "connectedgroup.h"

#include <algorithm>
#include <cassert>
#include <iostream>

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
  if (m_elementToGroup.find(index) == m_elementToGroup.end()) {
    m_elementToGroup[index] = m_groupToElement.size();
    std::set<size_t> group;
    group.insert(index);
    m_groupToElement.push_back(group);
  }
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
  m_elementToGroup.erase(index);
  m_groupToElement[group].erase(index);
  addElement(index);
  checkRemove(m_groupToElement);
}

void ConnectedGroup::removeConnection(size_t a, size_t b,
                                      const std::set<size_t>& neighbors)
{
  assert(m_elementToGroup.find(a) != m_elementToGroup.end());
  assert(m_elementToGroup.find(b) != m_elementToGroup.end());
  assert(m_elementToGroup[a] == m_elementToGroup[b]);
  removeConnection(a);
  size_t aGroup = m_elementToGroup[a];
  size_t bGroup = m_elementToGroup[b];
  for (const auto& n : neighbors) {
    m_groupToElement[bGroup].erase(n);
    m_groupToElement[aGroup].insert(n);
    m_elementToGroup[n] = aGroup;
  }
  checkRemove(m_groupToElement);
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
