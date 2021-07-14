/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BIMAP_H
#define AVOGADRO_CORE_BIMAP_H

#include "avogadrocore.h"

#include <map>
#include <set>
#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class ConnectedGroup bimap.h <avogadro/core/graph.h>
 * @brief The ConnectedGroup class represents a bidirectional Map data structure
 * between size_t (group) and a size_t set (nodes).
 * @example graph.h where it computes the bonded atom sets
 */
class AVOGADROCORE_EXPORT ConnectedGroup
{
public:
  /** Creates a new, empty ConnectedGroup. */
  ConnectedGroup();

  /** Creates a new ConnectedGroup containing size @p n vertices. */
  explicit ConnectedGroup(size_t n);

  /** Destroys the ConnectedGroup. */
  ~ConnectedGroup();

  /** check if @p index is already in a group otherwise create one for it */
  void addNode(size_t index);

  /** create @p n groups with 1 node each */
  void addNodes(size_t n);

  /** node @p a and @p b will be in the same group */
  void addConnection(size_t a, size_t b);

  /** Removes the node at @p index. */
  void removeNode(size_t index);

  /** Makes all the nodes individual groups. */
  void removeConnections();

  /** Makes @p index an individual group. */
  void removeConnection(size_t index);

  /** Checks if @p a and @p b whould be still connected and separate them if
   * they don't */
  void removeConnection(size_t a, size_t b, const std::set<size_t>& neighbors);

  /** Removes everything. */
  void clear();

  /** @return the group ID from the node . */
  size_t getGroup(size_t node) const;

  /** @return the group size from the node. */
  size_t getGroupSize(size_t node) const;

  /** @return all groups and their nodes */
  std::vector<std::set<size_t>> getAllGroups() const;

  /** @return all the nodes in the @p group. */
  std::set<size_t> getNodes(size_t group) const;

  /** @return the total groups existing */
  size_t groupCount() const;

private:
  std::map<size_t, size_t> m_nodeToGroup;
  std::vector<std::set<size_t>> m_groupToNode;

  void resetToSize(size_t n);
  void mergeGroups(size_t a, size_t b);
  void cleanConnection(size_t newGroup, size_t oldGroup,
                       const std::vector<size_t>& neighbors);
};

} // namespace Core
} // namespace Avogadro

#endif
