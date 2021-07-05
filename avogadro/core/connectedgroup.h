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
 * between size_t and a size_t set.
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

  /** Adds a element to the graph and returns its index. */
  void addElement(size_t index);

  /** Adds N element to the graph and returns its index. */
  void addElements(size_t n);

  /** Merge the two groups between two IDs @p a and @p b. */
  void addConnection(size_t a, size_t b);

  /** Removes the element at @p index. */
  void removeElement(size_t index);

  /** Makes all the element individual groups. */
  void removeConnections();

  /** Makes @p index an individual group. */
  void removeConnection(size_t index);

  /** Checks if @p a and @p b whould be still connected and separate them if
   * they don't */
  void removeConnection(size_t a, size_t b, const std::set<size_t>& neighbors);

  /** Removes all elements and groups. */
  void clear();

  /** Get the group ID from the element. */
  size_t getGroup(size_t element) const;

  /** Get the group size from the element. */
  size_t getGroupSize(size_t element) const;

  /** Get all the groups and their elemenets. */
  std::vector<std::set<size_t>> getAllGroups() const;

  /** Get all the elements in the @p group. */
  std::set<size_t> getElements(size_t group) const;

  /** */
  size_t groupCount() const;

private:
  std::map<size_t, size_t> m_elementToGroup;
  std::vector<std::set<size_t>> m_groupToElement;

  void resetToSize(size_t n);
  void mergeGroups(size_t a, size_t b);
  void cleanConnection(size_t newGroup, size_t oldGroup,
                       const std::vector<size_t>& neighbors);
};

} // namespace Core
} // namespace Avogadro

#endif
