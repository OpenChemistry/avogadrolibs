/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SELECTIONCOLUMN_H
#define AVOGADRO_CORE_SELECTIONCOLUMN_H

#include "avogadrocore.h"

#include <utility>
#include <vector>

namespace Avogadro::Core {

/**
 * @class SelectionColumn selectioncolumn.h <avogadro/core/selectioncolumn.h>
 * @brief The per-atom selection flags, with the same interface as Column.
 *
 * @note This is an implementation detail of Core::Molecule. It is installed
 * only because molecule.h holds it by value. Use the Molecule accessors.
 *
 * The storage is a std::vector<bool>, which Column<bool> cannot wrap
 * (Array<bool> would work, but the storage type is kept). This class offers
 * the member functions that Column does, with the same rules, so a state
 * struct can walk it alongside its Column members. It is optional: it may be
 * shorter than the atom count, and an atom without an entry is not selected.
 * The fill is fixed at false.
 */
class SelectionColumn
{
public:
  /** @return the number of entries (not the number of atoms). */
  Index size() const { return m_values.size(); }
  bool empty() const { return m_values.empty(); }

  /** @return true if atom @p index has an entry. */
  bool hasEntry(Index index) const { return index < m_values.size(); }

  /** The raw storage. */
  std::vector<bool>& storage() { return m_values; }
  const std::vector<bool>& storage() const { return m_values; }

  /**
   * Exchange the entries of atoms @p a and @p b: both have an entry (plain
   * swap); only the lower index has one (grow to cover the higher, new
   * entries false, then swap); neither does (nothing to do).
   */
  void swapEntries(Index a, Index b)
  {
    const Index lo = a < b ? a : b;
    const Index hi = a < b ? b : a;
    if (m_values.size() <= lo)
      return;
    if (m_values.size() <= hi)
      m_values.resize(hi + 1, false);
    // Not std::swap: it is a trap on the vector<bool> proxy reference.
    const bool temp = m_values[a];
    m_values[a] = m_values[b];
    m_values[b] = temp;
  }

  /**
   * Remove the entry of atom @p index by swap-and-pop. @p count is the number
   * of atoms before the removal. If the column covers every atom it
   * reindexes as the atoms do. If it is shorter but reaches @p index, the
   * entry is reset to false (the former last atom has none). Otherwise
   * nothing changes.
   */
  void removeEntry(Index index, Index count)
  {
    if (m_values.size() == count) {
      if (index >= count)
        return;
      m_values[index] = m_values.back();
      m_values.pop_back();
    } else if (index < m_values.size()) {
      m_values[index] = false;
    }
  }

  /** Drop every entry for an atom at or past @p count. */
  void trimTo(Index count)
  {
    if (m_values.size() > count)
      m_values.resize(count);
  }

  /** Remove every entry. */
  void clear() { m_values.clear(); }

  /** Take @p other's entries, leaving it empty. */
  void takeFrom(SelectionColumn& other)
  {
    m_values = std::move(other.m_values);
    other.m_values.clear();
  }

  /**
   * Save what removeEntry(@p index, @p count) is about to change: 0 entries
   * if the column does not reach @p index; 1 (the value at @p index) if it
   * is shorter than @p count; 2 (that, then the value at count - 1) if it
   * covers every atom. Call before removeEntry().
   */
  SelectionColumn slice(Index index, Index count) const
  {
    SelectionColumn result;
    if (index >= m_values.size())
      return result;
    result.m_values.push_back(m_values[index]);
    if (m_values.size() == count)
      result.m_values.push_back(m_values[count - 1]);
    return result;
  }

  /**
   * Undo removeEntry(@p index, ...) given @p saved = slice(@p index, ...).
   * @p count is the number of atoms after the restoration. It assumes the
   * column is exactly as removeEntry() left it, and does nothing otherwise.
   */
  void restore(Index index, const SelectionColumn& saved, Index count)
  {
    if (saved.m_values.empty())
      return;
    if (saved.m_values.size() == 2) {
      if (index >= count || m_values.size() != count - 1)
        return;
      m_values.push_back(saved.m_values[1]);
      m_values[index] = saved.m_values[0];
    } else if (index < m_values.size()) {
      m_values[index] = saved.m_values[0];
    }
  }

private:
  std::vector<bool> m_values;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_SELECTIONCOLUMN_H
