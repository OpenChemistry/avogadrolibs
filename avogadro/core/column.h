/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_COLUMN_H
#define AVOGADRO_CORE_COLUMN_H

#include "array.h"
#include "avogadrocore.h"

#include <type_traits>
#include <utility>

namespace Avogadro::Core {

/**
 * @class Column column.h <avogadro/core/column.h>
 * @brief One optional per-atom or per-bond array, with the rules for keeping
 * it in step with its owner.
 *
 * @note This is an implementation detail of Core::Molecule. It is installed
 * only because molecule.h holds its components by value. Use the Molecule
 * accessors, not this class.
 *
 * A column holds one value per entity (atom or bond) in an Array<T>. A
 * required column always has exactly one entry per entity. An optional
 * column may be shorter: an entity added after the column was last set has
 * no entry and reads as a default. Setting one entry grows the column to
 * cover every entity. Removal is swap-and-pop: the last entity moves into
 * the hole.
 *
 * Copying follows Array: copy construction shares the data (copy on write)
 * and copy assignment deep-copies. There are deliberately no move
 * operations, since Array has none; use takeFrom().
 *
 * Fill. Growing a column, and resetting a stale entry, needs a value for
 * entities that have none. Every function that can do so takes a @p fill
 * argument, which is either
 *  - a callable taking the entity index and returning T, for defaults that
 *    depend on the entity (an atom's color is its element's), or
 *  - a plain T, used for every entity.
 * The overloads without a @p fill use T(). That is wrong for fixed-size
 * Eigen vectors, which T() leaves uninitialized, so pass a fill for those.
 *
 * Every @p count is the number of entities the owner has. The caller knows
 * it; the column does not.
 */
template <typename T>
class Column
{
public:
  Column() = default;

  /** @return the number of entries (not the number of entities). */
  Index size() const { return m_values.size(); }
  bool empty() const { return m_values.empty(); }

  /** @return true if entity @p index has an entry. */
  bool hasEntry(Index index) const { return index < m_values.size(); }

  /** @return the entry for @p index, or @p fallback if it has none. */
  T value(Index index, const T& fallback) const
  {
    return index < m_values.size() ? m_values[index] : fallback;
  }

  /**
   * Write @p v at @p index, first growing the column to @p count entries
   * (new entries are fill(i)) if @p index is past its end.
   * @return false, changing nothing, if @p index >= @p count.
   */
  template <typename Fill>
  bool set(Index index, const T& v, Index count, Fill fill)
  {
    if (index >= count)
      return false;
    if (index >= m_values.size())
      growTo(count, fill);
    m_values[index] = v;
    return true;
  }

  bool set(Index index, const T& v, Index count)
  {
    return set(index, v, count, T());
  }

  /**
   * Replace every entry with @p values. Accepted if it has exactly @p count
   * entries, or if it is empty and @p acceptEmpty is true (which clears the
   * column). Otherwise the column is left alone and false is returned.
   */
  bool setAll(const Array<T>& values, Index count, bool acceptEmpty)
  {
    if (values.size() == count || (acceptEmpty && values.empty())) {
      m_values = values;
      return true;
    }
    return false;
  }

  /** The raw storage, for callers that need an Array<T>&. */
  Array<T>& array() { return m_values; }
  const Array<T>& array() const { return m_values; }

  /**
   * Exchange the entries of entities @p a and @p b. Three cases: both have
   * an entry (plain swap); only the lower index has one (grow to cover the
   * higher, new entries being fill(i), then swap, so the value travels with
   * its entity); neither does (nothing to do). @p count is unused and is
   * accepted so that a Column and a PropertyMap take the same call.
   */
  template <typename Fill>
  void swapEntries(Index a, Index b, Index /*count*/, Fill fill)
  {
    using std::swap;
    const Index lo = a < b ? a : b;
    const Index hi = a < b ? b : a;
    if (m_values.size() > hi) {
      swap(m_values[a], m_values[b]);
    } else if (m_values.size() > lo) {
      m_values.reserve(hi + 1);
      for (Index i = m_values.size(); i <= hi; ++i)
        m_values.push_back(fillValue(fill, i));
      swap(m_values[a], m_values[b]);
    }
  }

  void swapEntries(Index a, Index b, Index count)
  {
    swapEntries(a, b, count, T());
  }

  /**
   * Remove the entry of entity @p index by swap-and-pop. @p count is the
   * number of entities before the removal. If the column covers every entity
   * it reindexes exactly as the entities do. If it is shorter but reaches
   * @p index, the entity moved into @p index (the former last one) has no
   * entry of its own, so the stale value is reset to fill(count - 1). If it
   * does not reach @p index nothing changes.
   */
  template <typename Fill>
  void removeEntry(Index index, Index count, Fill fill)
  {
    if (m_values.size() == count) {
      m_values.swapAndPop(index);
    } else if (index < m_values.size()) {
      m_values[index] = fillValue(fill, count - 1);
    }
  }

  void removeEntry(Index index, Index count) { removeEntry(index, count, T()); }

  /** Remove every entry. */
  void clear() { m_values.clear(); }

  /**
   * Give @p other's data to this column and leave @p other empty and
   * unshared, as the move operations of Molecule need.
   */
  void takeFrom(Column& other)
  {
    Array<T> empty;
    m_values.swap(other.m_values);
    other.m_values.swap(empty);
  }

  /**
   * Save what removeEntry(@p index, @p count, ...) is about to change, for
   * restore(). Call it before removeEntry(). The result has 0 entries if the
   * column does not reach @p index; 1 (the value at @p index) if it is
   * shorter than @p count; 2 (that, then the value at count - 1, which the
   * removal moves into @p index) if it covers every entity.
   */
  Column slice(Index index, Index count) const
  {
    Column result;
    if (index >= m_values.size())
      return result;
    result.m_values.push_back(m_values[index]);
    if (m_values.size() == count)
      result.m_values.push_back(m_values[count - 1]);
    return result;
  }

  /**
   * Undo removeEntry(@p index, ...) given @p saved = slice(@p index, ...).
   * @p count is the number of entities after the restoration. It assumes the
   * column is exactly as removeEntry() left it, and does nothing otherwise.
   */
  void restore(Index index, const Column& saved, Index count)
  {
    if (saved.m_values.empty())
      return;
    if (saved.m_values.size() == 2) {
      // Covered every entity before: one entry went at the end of the
      // column, and index took the last entry's value.
      if (index >= count || m_values.size() != count - 1)
        return;
      m_values.push_back(saved.m_values[1]);
      m_values[index] = saved.m_values[0];
    } else if (index < m_values.size()) {
      m_values[index] = saved.m_values[0];
    }
  }

private:
  template <typename Fill>
  static T fillValue(const Fill& fill, Index index)
  {
    // is_invocable_r, not is_invocable: an Eigen vector can be called with an
    // index too (its coefficient accessor), but returns a scalar, not a T.
    if constexpr (std::is_invocable_r_v<T, const Fill&, Index>)
      return static_cast<T>(fill(index));
    else
      return static_cast<T>(fill);
  }

  template <typename Fill>
  void growTo(Index count, const Fill& fill)
  {
    m_values.reserve(count);
    for (Index i = m_values.size(); i < count; ++i)
      m_values.push_back(fillValue(fill, i));
  }

  Array<T> m_values;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_COLUMN_H
