/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ATOMTUPLE_H
#define AVOGADRO_CORE_ATOMTUPLE_H

#include "array.h"
#include "avogadrocore.h"
#include "vector.h"

#include <avogadro/core/angletools.h>
#include <avogadro/core/unitcell.h>

#include <array>
#include <cmath>
#include <cstddef>
#include <optional>
#include <tuple>

namespace Avogadro::Core {

/**
 * @class AtomTuple atomtuple.h <avogadro/core/atomtuple.h>
 * @brief The atoms that name a distance, bond angle, dihedral, or
 * out-of-plane (Wilson) angle, with a single way to measure it.
 *
 * A tuple that is not well formed (an index of MaxIndex, or the same atom named
 * twice) is Kind::None: it names nothing and measures nothing.
 */
class AtomTuple
{
public:
  /** The kind of geometric coordinate the atoms name. */
  enum class Kind
  {
    None,
    Distance,
    Angle,
    Dihedral,
    OutOfPlane
  };

  /** Create an empty tuple (Kind::None). */
  AtomTuple() = default;

  /** Create a distance between atoms @p a and @p b. */
  AtomTuple(Index a, Index b) noexcept
  {
    set(Kind::Distance, { a, b, MaxIndex, MaxIndex }, 2);
  }

  /** Create a bond angle a-b-c, where @p b is the vertex. */
  AtomTuple(Index a, Index b, Index c) noexcept
  {
    set(Kind::Angle, { a, b, c, MaxIndex }, 3);
  }

  /** Create a dihedral a-b-c-d. */
  AtomTuple(Index a, Index b, Index c, Index d) noexcept
  {
    set(Kind::Dihedral, { a, b, c, d }, 4);
  }

  /** Create a bond angle from the tuple used by AngleIterator. */
  explicit AtomTuple(const std::tuple<Index, Index, Index>& angle) noexcept
    : AtomTuple(std::get<0>(angle), std::get<1>(angle), std::get<2>(angle))
  {
  }

  /** Create a dihedral from the tuple used by DihedralIterator. */
  explicit AtomTuple(
    const std::tuple<Index, Index, Index, Index>& dihedral) noexcept
    : AtomTuple(std::get<0>(dihedral), std::get<1>(dihedral),
                std::get<2>(dihedral), std::get<3>(dihedral))
  {
  }

  /**
   * Create the Wilson angle of @p outOfPlaneAtom from the plane
   * @p center - @p b - @p c, in the same atom order as outOfPlaneAngle().
   */
  static AtomTuple outOfPlane(Index center, Index b, Index c,
                              Index outOfPlaneAtom) noexcept
  {
    AtomTuple tuple;
    tuple.set(Kind::OutOfPlane, { center, b, c, outOfPlaneAtom }, 4);
    return tuple;
  }

  /** @return The kind of coordinate this tuple names. */
  Kind kind() const noexcept { return m_kind; }

  /** @return True if the tuple names a coordinate (kind() is not None). */
  bool isValid() const noexcept { return m_kind != Kind::None; }

  /** @return The number of atoms: 0, 2, 3, or 4. */
  size_t size() const noexcept
  {
    switch (m_kind) {
      case Kind::Distance:
        return 2;
      case Kind::Angle:
        return 3;
      case Kind::Dihedral:
      case Kind::OutOfPlane:
        return 4;
      case Kind::None:
        break;
    }
    return 0;
  }

  /** @return The atom index at position @p i, or MaxIndex if out of range. */
  Index atom(size_t i) const noexcept
  {
    return i < size() ? m_atoms[i] : MaxIndex;
  }

  /** @return Pointer to the first atom, for range-based for loops. */
  const Index* begin() const noexcept { return m_atoms.data(); }

  /** @return Pointer one past the last atom (size() atoms are covered). */
  const Index* end() const noexcept { return m_atoms.data() + size(); }

  /**
   * @return The tuple read backwards (a-b-c-d becomes d-c-b-a). OutOfPlane
   * and None tuples have no reverse and are returned unchanged.
   */
  AtomTuple reversed() const noexcept
  {
    AtomTuple result = *this;
    if (m_kind == Kind::Distance || m_kind == Kind::Angle ||
        m_kind == Kind::Dihedral) {
      const size_t n = size();
      for (size_t i = 0; i < n; ++i)
        result.m_atoms[i] = m_atoms[n - 1 - i];
    }
    return result;
  }

  /**
   * @return True if @p other names the same coordinate in either direction:
   * it is equal to this tuple or (except for OutOfPlane) to its reverse. A
   * None tuple matches nothing, not even another None, and different kinds
   * never match.
   */
  bool matches(const AtomTuple& other) const noexcept
  {
    if (!isValid() || m_kind != other.m_kind)
      return false;
    return *this == other ||
           (m_kind != Kind::OutOfPlane && reversed() == other);
  }

  /** @return True if @p other has the same kind and the same atoms in order. */
  bool operator==(const AtomTuple& other) const noexcept
  {
    return m_kind == other.m_kind && m_atoms == other.m_atoms;
  }

  /** @return True if the tuples are not exactly equal. */
  bool operator!=(const AtomTuple& other) const noexcept
  {
    return !(*this == other);
  }

  /**
   * Measure the coordinate in @p positions.
   *
   * Positions are used as given: no periodic minimum image is applied, so
   * atoms in a periodic cell are measured across the raw coordinates.
   *
   * @return The value in Angstrom for a Distance, or in degrees otherwise:
   * Angle in [0, 180], Dihedral in [-180, 180] with the IUPAC sign, and
   * OutOfPlane in [-90, 90]. Returns std::nullopt if the tuple is not valid or
   * any index is outside @p positions, or the positions are not finite.
   */
  std::optional<Real> measure(const Array<Vector3>& positions) const noexcept
  {
    if (!inRange(positions))
      return std::nullopt;
    std::array<Vector3, 4> points;
    for (size_t i = 0; i < size(); ++i)
      points[i] = positions[m_atoms[i]];
    return measurePoints(points);
  }

  /**
   * Measure the coordinate across periodic boundaries.
   *
   * Unlike measure(), which uses raw Cartesian positions, each bonded step
   * (a-b, b-c, c-d) is taken as its shortest periodic image, so a coordinate
   * whose atoms were wrapped into opposite sides of the cell is measured as
   * one connected fragment. For an OutOfPlane tuple, each vector from the
   * center to b, c and the out-of-plane atom is taken as its shortest image.
   * The unwrapped points are then measured exactly as in measure().
   *
   * UnitCell::minimumImage() returns the shortest image of a vector (exact for
   * orthogonal and reduced cells). The result is still ambiguous when a step
   * is about half the cell's thinnest width, so the atoms should be bonded
   * neighbors, not far apart.
   *
   * @return The same units and ranges as measure(). Returns std::nullopt in
   * the cases measure() does (including non-finite positions), and also if @p
   * cell is singular (corrupt data is never measured, and there is no fallback
   * to measure()).
   */
  std::optional<Real> minimumImageMeasure(const Array<Vector3>& positions,
                                          const UnitCell& cell) const noexcept
  {
    if (!inRange(positions) || !cell.isRegular())
      return std::nullopt;

    std::array<Vector3, 4> points;
    if (m_kind == Kind::OutOfPlane) {
      const Vector3& center = positions[m_atoms[0]];
      points[0] = center;
      for (size_t i = 1; i < 4; ++i)
        points[i] = center + cell.minimumImage(positions[m_atoms[i]] - center);
    } else {
      points[0] = positions[m_atoms[0]];
      for (size_t i = 1; i < size(); ++i) {
        points[i] =
          points[i - 1] +
          cell.minimumImage(positions[m_atoms[i]] - positions[m_atoms[i - 1]]);
      }
    }
    return measurePoints(points);
  }

private:
  // True if the tuple is valid and every atom exists in @p positions.
  bool inRange(const Array<Vector3>& positions) const noexcept
  {
    const size_t n = size();
    if (n == 0)
      return false;
    for (size_t i = 0; i < n; ++i) {
      if (m_atoms[i] >= positions.size())
        return false;
    }
    return true;
  }

  // Measure the first size() points with the angletools functions.
  std::optional<Real> measurePoints(
    const std::array<Vector3, 4>& p) const noexcept
  {
    // The angletools helpers turn some NaN inputs into a finite 0 (a
    // zero-length bond has no angle), so check the points themselves too.
    for (size_t i = 0; i < size(); ++i) {
      if (!p[i].allFinite())
        return std::nullopt;
    }
    Real value = 0.0;
    switch (m_kind) {
      case Kind::Distance:
        value = (p[0] - p[1]).norm();
        break;
      case Kind::Angle:
        value = calculateAngle(p[0], p[1], p[2]);
        break;
      case Kind::Dihedral:
        value = calculateDihedral(p[0], p[1], p[2], p[3]);
        break;
      case Kind::OutOfPlane:
        value = outOfPlaneAngle(p[0], p[1], p[2], p[3]);
        break;
      case Kind::None:
        return std::nullopt;
    }
    // Corrupt positions must not yield a NaN wrapped in an optional.
    if (!std::isfinite(value))
      return std::nullopt;
    return value;
  }

  // Store the atoms if they are all set and distinct; otherwise stay None.
  void set(Kind kind, const std::array<Index, 4>& atoms, size_t count) noexcept
  {
    for (size_t i = 0; i < count; ++i) {
      if (atoms[i] == MaxIndex)
        return;
      for (size_t j = i + 1; j < count; ++j) {
        if (atoms[i] == atoms[j])
          return;
      }
    }
    m_atoms = atoms;
    m_kind = kind;
  }

  std::array<Index, 4> m_atoms{ MaxIndex, MaxIndex, MaxIndex, MaxIndex };
  Kind m_kind = Kind::None;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_ATOMTUPLE_H
