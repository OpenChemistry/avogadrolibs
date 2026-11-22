/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_FROZENMASKCOLUMN_H
#define AVOGADRO_CORE_FROZENMASKCOLUMN_H

#include "avogadrocore.h"
#include "vector.h"

#include <utility>

namespace Avogadro::Core {

/**
 * @class FrozenMaskColumn frozenmaskcolumn.h
 * <avogadro/core/frozenmaskcolumn.h>
 * @brief The per-atom frozen mask, with the same interface as Column.
 *
 * @note This is an implementation detail of Core::Molecule. It is installed
 * only because molecule.h holds it by value. Use the Molecule accessors.
 *
 * The storage is an Eigen::VectorXd with three rows per atom (x, y, z),
 * 1.0 for free and 0.0 for frozen. An "entry" is one atom's three rows, so
 * size() counts atoms, not rows. It offers the member functions that Column
 * does, with the same rules. It is optional: it may cover fewer atoms than
 * the molecule has, and an atom without an entry is not frozen. The fill is
 * fixed at 1.0 on every axis. A row count that is not a multiple of three
 * should not occur; the trailing partial entry is ignored.
 */
class FrozenMaskColumn
{
public:
  /** @return the number of entries (atoms), not the number of rows. */
  Index size() const { return static_cast<Index>(m_values.rows() / 3); }
  bool empty() const { return m_values.rows() == 0; }

  /** @return true if atom @p index has an entry. */
  bool hasEntry(Index index) const { return index < size(); }

  /** The raw storage, three rows per atom. */
  Eigen::VectorXd& storage() { return m_values; }
  const Eigen::VectorXd& storage() const { return m_values; }

  /**
   * Exchange the entries of atoms @p a and @p b: both have an entry (plain
   * swap); only the lower index has one (grow to cover the higher, new rows
   * 1.0, then swap); neither does (nothing to do).
   */
  void swapEntries(Index a, Index b)
  {
    const Index lo = a < b ? a : b;
    const Index hi = a < b ? b : a;
    if (!hasEntry(lo))
      return;
    if (!hasEntry(hi)) {
      const Eigen::Index oldRows = m_values.rows();
      m_values.conservativeResize(static_cast<Eigen::Index>(3 * (hi + 1)));
      for (Eigen::Index i = oldRows; i < m_values.rows(); ++i)
        m_values[i] = 1.0;
    }
    const auto ea = static_cast<Eigen::Index>(a);
    const auto eb = static_cast<Eigen::Index>(b);
    for (Eigen::Index i = 0; i < 3; ++i)
      std::swap(m_values[3 * ea + i], m_values[3 * eb + i]);
  }

  /**
   * Remove the entry of atom @p index by swap-and-pop. @p count is the number
   * of atoms before the removal. If the column covers every atom it
   * reindexes as the atoms do. If it is shorter but reaches @p index, the
   * entry is reset to 1.0 (the former last atom has none). Otherwise nothing
   * changes.
   */
  void removeEntry(Index index, Index count)
  {
    const auto eIndex = static_cast<Eigen::Index>(index);
    if (m_values.rows() == static_cast<Eigen::Index>(3 * count)) {
      if (index >= count)
        return;
      const Eigen::Index last = m_values.rows() - 3;
      for (Eigen::Index i = 0; i < 3; ++i)
        m_values[3 * eIndex + i] = m_values[last + i];
      m_values.conservativeResize(last);
    } else if (hasEntry(index)) {
      for (Eigen::Index i = 0; i < 3; ++i)
        m_values[3 * eIndex + i] = 1.0;
    }
  }

  /** Remove every entry. */
  void clear() { m_values.resize(0); }

  /** Take @p other's entries, leaving it empty. */
  void takeFrom(FrozenMaskColumn& other)
  {
    // Eigen's move assignment swaps, so empty the source explicitly.
    m_values = std::move(other.m_values);
    other.m_values.resize(0);
  }

  /**
   * Save what removeEntry(@p index, @p count) is about to change: 0 entries
   * if the column does not reach @p index; 1 (the entry at @p index) if it is
   * shorter than @p count; 2 (that, then the entry at count - 1) if it
   * covers every atom. Call before removeEntry().
   */
  FrozenMaskColumn slice(Index index, Index count) const
  {
    FrozenMaskColumn result;
    if (!hasEntry(index))
      return result;
    const bool full = m_values.rows() == static_cast<Eigen::Index>(3 * count);
    result.m_values.resize(full ? 6 : 3);
    result.m_values.head<3>() = m_values.segment<3>(3 * index);
    if (full)
      result.m_values.tail<3>() = m_values.segment<3>(3 * (count - 1));
    return result;
  }

  /**
   * Undo removeEntry(@p index, ...) given @p saved = slice(@p index, ...).
   * @p count is the number of atoms after the restoration. It assumes the
   * column is exactly as removeEntry() left it, and does nothing otherwise.
   */
  void restore(Index index, const FrozenMaskColumn& saved, Index count)
  {
    const Index entries = saved.size();
    if (entries == 0)
      return;
    if (entries == 2) {
      if (index >= count ||
          m_values.rows() != static_cast<Eigen::Index>(3 * (count - 1)))
        return;
      const Eigen::Index rows = m_values.rows();
      m_values.conservativeResize(rows + 3);
      m_values.tail<3>() = saved.m_values.tail<3>();
      m_values.segment<3>(3 * index) = saved.m_values.head<3>();
    } else if (hasEntry(index)) {
      m_values.segment<3>(3 * index) = saved.m_values.head<3>();
    }
  }

private:
  Eigen::VectorXd m_values;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_FROZENMASKCOLUMN_H
