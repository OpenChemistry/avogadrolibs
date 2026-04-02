/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_PROPERTYMAP_H
#define AVOGADRO_CORE_PROPERTYMAP_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"
#include "array.h"
#include "matrix.h"

#include <climits>
#include <cmath>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>

namespace Avogadro::Core {

/**
 * @class PropertyMap propertymap.h <avogadro/core/propertymap.h>
 * @brief A typed column store for per-entity custom properties.
 *
 * PropertyMap stores named columns of per-entity data (e.g., per-atom,
 * per-bond, or per-residue). It supports four column types:
 *
 *  - @c double — dense, stored in Array<double> (NaN sentinel internally)
 *  - @c int — dense, stored in Array<int> (INT_MIN sentinel internally)
 *  - @c std::string — dense, stored in Array<std::string> ("" sentinel)
 *  - @c MatrixX — sparse, stored in std::unordered_map<Index, MatrixX>
 *
 * Dense columns are always sized to the entity count. Sparse matrix columns
 * only store entries for entities that have data.
 *
 * Public getters return std::optional<T>, returning std::nullopt for missing
 * values or type mismatches. Sentinels are an internal storage detail.
 */
class AVOGADROCORE_EXPORT PropertyMap
{
public:
  PropertyMap() = default;

  // --- Per-index setters ---

  /** Set a double property value for entity at @p index. */
  void setDouble(const std::string& name, Index index, double value);

  /** Set an int property value for entity at @p index. */
  void setInt(const std::string& name, Index index, int value);

  /** Set a string property value for entity at @p index. */
  void setString(const std::string& name, Index index,
                 const std::string& value);

  /** Set a matrix property value for entity at @p index (sparse). */
  void setMatrix(const std::string& name, Index index, const MatrixX& value);

  // --- Per-index getters (return nullopt if missing or wrong type) ---

  /** @return the double value for @p name at @p index, or nullopt. */
  std::optional<double> getDouble(const std::string& name, Index index) const;

  /** @return the int value for @p name at @p index, or nullopt. */
  std::optional<int> getInt(const std::string& name, Index index) const;

  /** @return the string value for @p name at @p index, or nullopt. */
  std::optional<std::string> getString(const std::string& name,
                                       Index index) const;

  /** @return the matrix value for @p name at @p index, or nullopt. */
  std::optional<MatrixX> getMatrix(const std::string& name, Index index) const;

  // --- Bulk setters/getters ---

  /** Set an entire column of double values. */
  void setDoubles(const std::string& name, const Array<double>& values);

  /** @return the full double column for @p name, or empty array if absent. */
  const Array<double>& doubles(const std::string& name) const;

  /** Set an entire column of int values. */
  void setInts(const std::string& name, const Array<int>& values);

  /** @return the full int column for @p name, or empty array if absent. */
  const Array<int>& ints(const std::string& name) const;

  /** Set an entire column of string values. */
  void setStrings(const std::string& name, const Array<std::string>& values);

  /** @return the full string column for @p name, or empty array if absent. */
  const Array<std::string>& strings(const std::string& name) const;

  // --- Existence checks ---

  /** @return true if a double column named @p name exists. */
  bool hasDoubles(const std::string& name) const;

  /** @return true if an int column named @p name exists. */
  bool hasInts(const std::string& name) const;

  /** @return true if a string column named @p name exists. */
  bool hasStrings(const std::string& name) const;

  /** @return true if a matrix entry exists for @p name at @p index. */
  bool hasMatrix(const std::string& name, Index index) const;

  /** @return true if any matrix column named @p name exists. */
  bool hasMatrices(const std::string& name) const;

  // --- Name enumeration ---

  /** @return names of all double columns. */
  std::set<std::string> doubleNames() const;

  /** @return names of all int columns. */
  std::set<std::string> intNames() const;

  /** @return names of all string columns. */
  std::set<std::string> stringNames() const;

  /** @return names of all matrix columns. */
  std::set<std::string> matrixNames() const;

  // --- Structural operations (called by Molecule on add/remove/swap) ---

  /**
   * Append a default entry to all existing dense columns.
   * New columns are not created; only columns that already exist are extended.
   */
  void addEntry();

  /**
   * Remove the entry at @p index using swap-and-pop.
   * @p entityCount is the count before removal (used to check if columns
   * are at full size).
   */
  void removeEntry(Index index, Index entityCount);

  /**
   * Swap entries at indices @p a and @p b.
   * @p entityCount is the current entity count (used to check column sizes).
   */
  void swapEntries(Index a, Index b, Index entityCount);

  /** Clear all columns and data. */
  void clear();

  /** @return true if no columns exist. */
  bool empty() const;

private:
  std::map<std::string, Array<double>> m_doubles;
  std::map<std::string, Array<int>> m_ints;
  std::map<std::string, Array<std::string>> m_strings;
  std::map<std::string, std::unordered_map<Index, MatrixX>> m_matrices;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_PROPERTYMAP_H
