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

ConnectedGroup::ConnectedGroup(size_t n) : m_groupToNode(n)
{
  resetToSize(n);
}

void ConnectedGroup::addGroup(size_t group)
{
  for (auto& nodeGroup : m_nodeToGroup) {
    if (nodeGroup.second >= group) {
      ++nodeGroup.second;
    }
  }
  m_groupToNode.insert(m_groupToNode.begin() + group, std::set<size_t>());
}

ConnectedGroup::~ConnectedGroup() {}

void ConnectedGroup::addNode(size_t index)
{
  if (m_nodeToGroup.find(index) == m_nodeToGroup.end()) {
    m_nodeToGroup[index] = m_groupToNode.size();
    std::set<size_t> group;
    group.insert(index);
    m_groupToNode.push_back(group);
  }
}

void ConnectedGroup::addNode(size_t node, size_t group)
{
  assert(group < m_groupToNode.size());
  auto it = m_nodeToGroup.find(node);
  // if node already exists, remove it
  if (it == m_nodeToGroup.end()) {
    m_nodeToGroup[node] = group;
    m_groupToNode[group].insert(node);
  } else {
    auto old_group = m_nodeToGroup[node];
    m_nodeToGroup[node] = group;

    m_groupToNode[old_group].erase(node);
    m_groupToNode[group].insert(node);
  }
}

void ConnectedGroup::addNodes(size_t n)
{
  size_t offset = m_nodeToGroup.size();
  for (size_t i = 0; i < n; ++i) {
    addNode(i + offset);
  }
}

void ConnectedGroup::addNodes(size_t n, size_t group)
{
  size_t offset = m_nodeToGroup.size();
  for (size_t i = 0; i < n; ++i) {
    addNode(i + offset, group);
  }
}

void ConnectedGroup::addConnection(size_t a, size_t b)
{
  assert(m_nodeToGroup.find(a) != m_nodeToGroup.end());
  assert(m_nodeToGroup.find(b) != m_nodeToGroup.end());

  size_t group_a = m_nodeToGroup[a];
  size_t group_b = m_nodeToGroup[b];
  if (group_a != group_b) {
    // add everything in b to group a
    for (size_t node : m_groupToNode[group_b]) {
      m_nodeToGroup[node] = group_a;
      m_groupToNode[group_a].insert(node);
    }
    m_groupToNode[group_b].clear();
    // TODO: remove empty groups
    checkRemove(m_groupToNode);
  }
}

void ConnectedGroup::removeNode(size_t index)
{
  auto it = m_nodeToGroup.find(index);
  if (it != m_nodeToGroup.end()) {
    size_t group = it->second;
    m_nodeToGroup.erase(it);
    m_groupToNode[group].erase(index);
    checkRemove(m_groupToNode);
  }
}

void ConnectedGroup::removeConnections()
{
  size_t n = m_nodeToGroup.size();
  clear();
  resetToSize(n);
}

void ConnectedGroup::removeConnection(size_t index)
{
  assert(m_nodeToGroup.find(index) != m_nodeToGroup.end());
  size_t group = m_nodeToGroup[index];
  m_nodeToGroup.erase(index);
  m_groupToNode[group].erase(index);
  addNode(index);
  checkRemove(m_groupToNode);
}

void ConnectedGroup::removeConnection(size_t a, size_t b,
                                      const std::set<size_t>& neighbors)
{
  assert(m_nodeToGroup.find(a) != m_nodeToGroup.end());
  assert(m_nodeToGroup.find(b) != m_nodeToGroup.end());
  if (m_nodeToGroup[a] != m_nodeToGroup[b]) {
    return;
  }
  removeConnection(a);
  size_t aGroup = m_nodeToGroup[a];
  size_t bGroup = m_nodeToGroup[b];
  for (const auto& n : neighbors) {
    m_groupToNode[bGroup].erase(n);
    m_groupToNode[aGroup].insert(n);
    m_nodeToGroup[n] = aGroup;
  }
  checkRemove(m_groupToNode);
}

void ConnectedGroup::removeGroup(size_t group)
{
  assert(group < m_nodeToGroup.size());
  auto it = m_nodeToGroup.begin();
  while (it != m_nodeToGroup.end()) {
    if (it->second > group) {
      --it->second;
      ++it;
    } else if (it->second == group) {
      it = m_nodeToGroup.erase(it);
    } else {
      ++it;
    }
  }

  m_groupToNode.erase(m_groupToNode.begin() + group);
}

void ConnectedGroup::clear()
{
  m_nodeToGroup.clear();
  m_groupToNode.clear();
}

size_t ConnectedGroup::getGroup(size_t node) const
{
  assert(m_nodeToGroup.find(node) != m_nodeToGroup.end());
  return m_nodeToGroup.at(node);
}

std::set<size_t> ConnectedGroup::getNodes(size_t group) const
{
  assert(group < m_groupToNode.size());
  return m_groupToNode[group];
}

std::vector<std::set<size_t>> ConnectedGroup::getAllGroups() const
{
  // Only return non-empty groups
  std::vector<std::set<size_t>> groups;
  for (const auto& group : m_groupToNode) {
    if (group.size() > 0) {
      groups.push_back(group);
    }
  }
  return groups;
}

void ConnectedGroup::resetToSize(size_t n)
{
  for (size_t i = 0; i < n; ++i) {
    m_nodeToGroup[i] = i;
    m_groupToNode[i].insert(i);
  }
}

size_t ConnectedGroup::groupCount() const
{
  return m_groupToNode.size();
}

size_t ConnectedGroup::atomCount() const
{
  return m_nodeToGroup.size();
}

size_t ConnectedGroup::getGroupSize(size_t node) const
{
  return m_groupToNode.at(m_nodeToGroup.at(node)).size();
}

bool ConnectedGroup::hasAtom(size_t atom) const
{
  return m_nodeToGroup.find(atom) != m_nodeToGroup.end();
}

} // namespace Core
} // namespace Avogadro
