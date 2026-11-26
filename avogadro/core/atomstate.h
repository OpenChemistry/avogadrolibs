/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ATOMSTATE_H
#define AVOGADRO_CORE_ATOMSTATE_H

#include "array.h"
#include "atom.h"
#include "avogadrocore.h"
#include "column.h"
#include "elements.h"
#include "frozenmaskcolumn.h"
#include "propertymap.h"
#include "vector.h"

#include <string>
#include <type_traits>

namespace Avogadro::Core {

/**
 * @class AtomState atomstate.h <avogadro/core/atomstate.h>
 * @brief Everything Core::Molecule stores per atom as an optional column, with
 * the rules for keeping it in step with the atoms.
 *
 * @note This is an implementation detail of Core::Molecule, installed only
 * because molecule.h holds it by value. Use the Molecule accessors.
 *
 * It follows BondState: a plain list of columns plus a PropertyMap, named
 * once in forEachColumn(), with every operation written on top of that.
 * Molecule holds one instance and calls swapEntries(), removeEntry() and
 * clear() from its atom operations and takeFrom() from its move operations;
 * it never lists the columns. slice() and restore() save and put back one
 * atom's entries, so an undo command needs no column list.
 *
 * The rule for a new per-atom state member: add it to forEachColumn() and
 * nowhere else.
 *
 * Not held here: the atomic numbers (required, and the graph's vertices), the
 * 3D positions and coordinate sets, velocities, forces, partial charges,
 * vibrations, layers, residues and constraints. Molecule handles those
 * itself.
 *
 * Every @p count is the number of atoms. All the columns are optional and
 * may be shorter than that; see column.h and propertymap.h for the rules.
 *
 * Fills. Swapping and removing can grow a column or reset a stale entry, which
 * needs a value for atoms with none. Most fills are fixed, but the color of
 * an atom is its element's, so swapEntries() and removeEntry() take the
 * molecule's atomic numbers. They must run before Molecule updates its atomic
 * numbers, because the color fill reads them at the pre-operation indices.
 */
struct AtomState
{
  /** Marks a column whose operations take no fill (see the helpers below). */
  struct NoFill
  {};

  /**
   * The default color of an atom: its element's. An index that is null or
   * out of range of the atomic numbers gets the color of atomic number 0,
   * which is what Elements::color() returns for any number it does not know
   * (the dummy element's, a gray), so it can never read out of bounds.
   */
  struct ColorFill
  {
    const Array<unsigned char>* atomicNumbers = nullptr;

    Vector3ub operator()(Index index) const
    {
      const unsigned char number =
        (atomicNumbers != nullptr && index < atomicNumbers->size())
          ? (*atomicNumbers)[index]
          : static_cast<unsigned char>(0);
      return Vector3ub(Elements::color(number));
    }
  };

  Column<Vector2> positions2d;
  Column<std::string> labels;
  Column<AtomHybridization> hybridizations;
  Column<signed char> formalCharges;
  Column<unsigned short> isotopes;
  Column<double> occupancies; // crystallographic site occupancy, 0-1
  // CIF disorder assembly and group labels, "" for an ordered atom
  Column<std::string> disorderAssemblies;
  Column<std::string> disorderGroups;
  Column<Vector3ub> colors;
  Column<unsigned char> selection; // 0 = not selected, 1 = selected
  FrozenMaskColumn frozenMask;
  PropertyMap properties;

  /**
   * Call @p f(column, fill, other column...) for every column. The color fill
   * reads @p atomicNumbers, which may be null for the operations that need no
   * fill (clear, slice, restore, takeFrom). @p fill is
   * what the column's swapEntries() and removeEntry() take: a value, a
   * callable, or NoFill for a column that takes none. Each extra AtomState in
   * @p others is visited alongside, so that slice(), restore() and takeFrom()
   * can walk two states in step.
   */
  template <typename F, typename... Others>
  void forEachColumn(const Array<unsigned char>* atomicNumbers, F&& f,
                     Others&... others)
  {
    f(positions2d, Vector2(Vector2::Zero()), others.positions2d...);
    f(labels, NoFill(), others.labels...);
    f(hybridizations, NoFill(), others.hybridizations...);
    f(formalCharges, NoFill(), others.formalCharges...);
    f(isotopes, NoFill(), others.isotopes...);
    // an atom with no stored occupancy fills the site completely
    f(occupancies, 1.0, others.occupancies...);
    // an atom with no stored label is ordered ("")
    f(disorderAssemblies, NoFill(), others.disorderAssemblies...);
    f(disorderGroups, NoFill(), others.disorderGroups...);
    f(colors, ColorFill{ atomicNumbers }, others.colors...);
    f(selection, NoFill(), others.selection...);
    f(frozenMask, NoFill(), others.frozenMask...);
    f(properties, NoFill(), others.properties...);
  }

  /**
   * Add the entries of a new atom. @p count is the number of atoms after the
   * addition. Only the custom properties get an entry (their unset value);
   * every other column is optional, so the new atom has none.
   */
  void addEntry(Index count) { properties.addEntry(count); }

  /**
   * Exchange everything stored for atoms @p a and @p b. @p atomicNumbers are
   * the molecule's, not yet swapped.
   */
  void swapEntries(Index a, Index b, const Array<unsigned char>& atomicNumbers)
  {
    forEachColumn(&atomicNumbers, [&](auto& column, const auto& fill) {
      swapColumn(column, a, b, fill);
    });
  }

  /**
   * Remove atom @p index by swap-and-pop. @p count is before the removal and
   * @p atomicNumbers are the molecule's, not yet shortened.
   */
  void removeEntry(Index index, Index count,
                   const Array<unsigned char>& atomicNumbers)
  {
    forEachColumn(&atomicNumbers, [&](auto& column, const auto& fill) {
      removeColumn(column, index, count, fill);
    });
  }

  /** Remove everything stored for every atom. */
  void clear()
  {
    forEachColumn(nullptr, [](auto& column, const auto&) { column.clear(); });
  }

  /**
   * Save what removeEntry(@p index, @p count, ...) is about to change. Call it
   * before removeEntry(); restore() takes the result.
   */
  AtomState slice(Index index, Index count) const
  {
    AtomState result;
    result.forEachColumn(
      nullptr,
      [&](auto& saved, const auto&, const auto& column) {
        saved = column.slice(index, count);
      },
      *this);
    return result;
  }

  /**
   * Undo removeEntry(@p index, ...) using @p saved from slice(). @p count is
   * the number of atoms after the restoration. The caller has to put the atom
   * itself back first; this restores only what the state stores for it.
   * @p atomicNumbers are those of the molecule after the restoration, which
   * the color of an atom without one is derived from. This also copes with a
   * color column that an undone setter left grown (see Column::restore() with
   * a fill).
   */
  void restore(Index index, const AtomState& saved, Index count,
               const Array<unsigned char>& atomicNumbers)
  {
    forEachColumn(
      &atomicNumbers,
      [&](auto& column, const auto& fill, const auto& part) {
        restoreColumn(column, index, part, count, fill);
      },
      saved);
  }

  /**
   * Take @p other's contents, leaving it equivalent to a default-constructed
   * state: empty and unshared. This is the move operation, since Array has
   * none.
   */
  void takeFrom(AtomState& other)
  {
    forEachColumn(
      nullptr,
      [](auto& column, const auto&, auto& source) { column.takeFrom(source); },
      other);
  }

private:
  template <typename Column, typename Fill>
  static void restoreColumn(Column& column, Index index, const Column& saved,
                            Index count, const Fill& fill)
  {
    if constexpr (std::is_same_v<Fill, NoFill>)
      column.restore(index, saved, count);
    else
      column.restore(index, saved, count, fill);
  }

  // The columns that take no fill have swapEntries(a, b) and
  // removeEntry(index, count) only (or, for Column, the T() default), and
  // PropertyMap's public API is deliberately left without a tag overload, so
  // dispatch here.
  template <typename Column, typename Fill>
  static void swapColumn(Column& column, Index a, Index b, const Fill& fill)
  {
    if constexpr (std::is_same_v<Fill, NoFill>)
      column.swapEntries(a, b);
    else
      column.swapEntries(a, b, fill);
  }

  template <typename Column, typename Fill>
  static void removeColumn(Column& column, Index index, Index count,
                           const Fill& fill)
  {
    if constexpr (std::is_same_v<Fill, NoFill>)
      column.removeEntry(index, count);
    else
      column.removeEntry(index, count, fill);
  }
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_ATOMSTATE_H
