/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BONDSTATE_H
#define AVOGADRO_CORE_BONDSTATE_H

#include "avogadrocore.h"
#include "column.h"
#include "propertymap.h"

#include <string>

namespace Avogadro::Core {

/**
 * @class BondState bondstate.h <avogadro/core/bondstate.h>
 * @brief Everything Core::Molecule stores per bond, other than the graph.
 *
 * @note This is an implementation detail of Core::Molecule, installed only
 * because molecule.h holds it by value. Use the Molecule accessors.
 *
 * The pattern for the next components (atom state, results, trajectory):
 * the struct is a plain list of Column<T> members, plus a PropertyMap for
 * custom properties. The columns are named once, in forEachColumn(), and
 * every operation is written with it, so a new column is one member and one
 * line there. Molecule holds one instance and calls swapEntries(),
 * removeEntry() and clear() from its bond operations and takeFrom() from its
 * move operations; it never lists the columns. slice() and restore() save
 * and put back one bond's entries, so an undo command needs no column list.
 * Copying is the defaulted memberwise copy, as for a bare Array.
 *
 * Every @p count is the number of bonds. The orders column is required (one
 * entry per bond, added by Molecule::addBond()); labels are optional and may
 * be shorter. See column.h and propertymap.h for the rules.
 */
struct BondState
{
  Column<unsigned char> orders;
  Column<std::string> labels;
  PropertyMap properties;

  /**
   * Call @p f(column) for every column, orders first. Each extra BondState in
   * @p others is visited alongside, as f(column, other column...), so that
   * slice(), restore() and takeFrom() can walk two states in step.
   */
  template <typename F, typename... Others>
  void forEachColumn(F&& f, Others&... others)
  {
    f(orders, others.orders...);
    f(labels, others.labels...);
    f(properties, others.properties...);
  }

  /** Exchange everything stored for bonds @p a and @p b. */
  void swapEntries(Index a, Index b)
  {
    forEachColumn([&](auto& column) { column.swapEntries(a, b); });
  }

  /** Remove bond @p index by swap-and-pop. @p count is before the removal. */
  void removeEntry(Index index, Index count)
  {
    forEachColumn([&](auto& column) { column.removeEntry(index, count); });
  }

  /** Remove everything stored for every bond. */
  void clear()
  {
    forEachColumn([](auto& column) { column.clear(); });
  }

  /**
   * Save what removeEntry(@p index, @p count) is about to change. Call it
   * before removeEntry(); restore() takes the result.
   */
  BondState slice(Index index, Index count) const
  {
    BondState result;
    result.forEachColumn(
      [&](auto& saved, const auto& column) {
        saved = column.slice(index, count);
      },
      *this);
    return result;
  }

  /**
   * Undo removeEntry(@p index, ...) using @p saved from slice(). @p count is
   * the number of bonds after the restoration. The graph has to put the bond
   * back first; this restores only what the state stores for it.
   */
  void restore(Index index, const BondState& saved, Index count)
  {
    forEachColumn([&](auto& column,
                      const auto& part) { column.restore(index, part, count); },
                  saved);
  }

  /**
   * Take @p other's contents, leaving it equivalent to a default-constructed
   * state: empty and unshared. This is the move operation, since Array has
   * none.
   */
  void takeFrom(BondState& other)
  {
    forEachColumn([](auto& column, auto& source) { column.takeFrom(source); },
                  other);
  }
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_BONDSTATE_H
