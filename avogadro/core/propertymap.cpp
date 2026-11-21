/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymap.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace Avogadro::Core {

// Internal sentinel values for dense columns.
static const double doubleSentinel = std::numeric_limits<double>::quiet_NaN();
static const int intSentinel = std::numeric_limits<int>::min();

// --- Per-index setters ---

void PropertyMap::setDouble(const std::string& name, Index index, double value)
{
  auto& col = m_doubles[name].array();
  if (col.size() <= index)
    col.resize(index + 1, doubleSentinel);
  col[index] = value;
}

void PropertyMap::setInt(const std::string& name, Index index, int value)
{
  auto& col = m_ints[name].array();
  if (col.size() <= index)
    col.resize(index + 1, intSentinel);
  col[index] = value;
}

void PropertyMap::setString(const std::string& name, Index index,
                            const std::string& value)
{
  auto& col = m_strings[name].array();
  if (col.size() <= index)
    col.resize(index + 1, std::string());
  col[index] = value;
}

void PropertyMap::setMatrix(const std::string& name, Index index,
                            const MatrixX& value)
{
  m_matrices[name][index] = value;
}

// --- Per-index getters ---

std::optional<double> PropertyMap::getDouble(const std::string& name,
                                             Index index) const
{
  auto it = m_doubles.find(name);
  if (it == m_doubles.end() || !it->second.hasEntry(index))
    return std::nullopt;
  double val = it->second.array()[index];
  if (std::isnan(val))
    return std::nullopt;
  return val;
}

std::optional<int> PropertyMap::getInt(const std::string& name,
                                       Index index) const
{
  auto it = m_ints.find(name);
  if (it == m_ints.end() || !it->second.hasEntry(index))
    return std::nullopt;
  int val = it->second.array()[index];
  if (val == intSentinel)
    return std::nullopt;
  return val;
}

std::optional<std::string> PropertyMap::getString(const std::string& name,
                                                  Index index) const
{
  auto it = m_strings.find(name);
  if (it == m_strings.end() || !it->second.hasEntry(index))
    return std::nullopt;
  const std::string& val = it->second.array()[index];
  if (val.empty())
    return std::nullopt;
  return val;
}

std::optional<MatrixX> PropertyMap::getMatrix(const std::string& name,
                                              Index index) const
{
  auto colIt = m_matrices.find(name);
  if (colIt == m_matrices.end())
    return std::nullopt;
  auto entryIt = colIt->second.find(index);
  if (entryIt == colIt->second.end())
    return std::nullopt;
  return entryIt->second;
}

// --- Bulk setters/getters ---

void PropertyMap::createDoubles(const std::string& name, Index count)
{
  if (m_doubles.find(name) != m_doubles.end())
    return;
  m_doubles[name].array() = Array<double>(count, doubleSentinel);
}

void PropertyMap::createInts(const std::string& name, Index count)
{
  if (m_ints.find(name) != m_ints.end())
    return;
  m_ints[name].array() = Array<int>(count, intSentinel);
}

void PropertyMap::createStrings(const std::string& name, Index count)
{
  if (m_strings.find(name) != m_strings.end())
    return;
  m_strings[name].array() = Array<std::string>(count, std::string());
}

void PropertyMap::setDoubles(const std::string& name,
                             const Array<double>& values)
{
  m_doubles[name].array() = values;
}

const Array<double>& PropertyMap::doubles(const std::string& name) const
{
  static const Array<double> empty;
  auto it = m_doubles.find(name);
  if (it != m_doubles.end())
    return it->second.array();
  return empty;
}

void PropertyMap::setInts(const std::string& name, const Array<int>& values)
{
  m_ints[name].array() = values;
}

const Array<int>& PropertyMap::ints(const std::string& name) const
{
  static const Array<int> empty;
  auto it = m_ints.find(name);
  if (it != m_ints.end())
    return it->second.array();
  return empty;
}

void PropertyMap::setStrings(const std::string& name,
                             const Array<std::string>& values)
{
  m_strings[name].array() = values;
}

const Array<std::string>& PropertyMap::strings(const std::string& name) const
{
  static const Array<std::string> empty;
  auto it = m_strings.find(name);
  if (it != m_strings.end())
    return it->second.array();
  return empty;
}

const std::unordered_map<Index, MatrixX>& PropertyMap::matrices(
  const std::string& name) const
{
  static const std::unordered_map<Index, MatrixX> empty;
  auto it = m_matrices.find(name);
  if (it != m_matrices.end())
    return it->second;
  return empty;
}

// --- Existence checks ---

bool PropertyMap::hasDoubles(const std::string& name) const
{
  return m_doubles.find(name) != m_doubles.end();
}

bool PropertyMap::hasInts(const std::string& name) const
{
  return m_ints.find(name) != m_ints.end();
}

bool PropertyMap::hasStrings(const std::string& name) const
{
  return m_strings.find(name) != m_strings.end();
}

bool PropertyMap::hasMatrix(const std::string& name, Index index) const
{
  auto colIt = m_matrices.find(name);
  if (colIt == m_matrices.end())
    return false;
  return colIt->second.find(index) != colIt->second.end();
}

bool PropertyMap::hasMatrices(const std::string& name) const
{
  return m_matrices.find(name) != m_matrices.end();
}

// --- Name enumeration ---

std::set<std::string> PropertyMap::doubleNames() const
{
  std::set<std::string> names;
  for (const auto& kv : m_doubles)
    names.insert(kv.first);
  return names;
}

std::set<std::string> PropertyMap::intNames() const
{
  std::set<std::string> names;
  for (const auto& kv : m_ints)
    names.insert(kv.first);
  return names;
}

std::set<std::string> PropertyMap::stringNames() const
{
  std::set<std::string> names;
  for (const auto& kv : m_strings)
    names.insert(kv.first);
  return names;
}

std::set<std::string> PropertyMap::matrixNames() const
{
  std::set<std::string> names;
  for (const auto& kv : m_matrices)
    names.insert(kv.first);
  return names;
}

// --- Structural operations ---

void PropertyMap::addEntry(Index entityCount)
{
  for (auto& kv : m_doubles)
    kv.second.addEntry(entityCount, doubleSentinel);
  for (auto& kv : m_ints)
    kv.second.addEntry(entityCount, intSentinel);
  for (auto& kv : m_strings)
    kv.second.addEntry(entityCount, std::string());
  // Sparse matrices: the new entity has no entry.
  const Index index = entityCount > 0 ? entityCount - 1 : 0;
  for (auto& kv : m_matrices) {
    auto& col = kv.second;
    for (auto it = col.begin(); it != col.end();) {
      if (it->first >= index)
        it = col.erase(it);
      else
        ++it;
    }
  }
}

namespace {

// The dense columns follow the rules of Column, with the unset sentinel of
// the type as the fill. Entries past the entity count belong to no entity
// (the setters don't check the index); Column drops them on removal.

template <typename T>
void removeDense(std::map<std::string, Column<T>>& columns, Index index,
                 Index entityCount, const T& sentinel)
{
  for (auto& kv : columns)
    kv.second.removeEntry(index, entityCount, sentinel);
}

template <typename T>
void swapDense(std::map<std::string, Column<T>>& columns, Index a, Index b,
               const T& sentinel)
{
  for (auto& kv : columns)
    kv.second.swapEntries(a, b, sentinel);
}

// Columns with nothing to save are left out of @p out.
template <typename T>
void sliceDense(const std::map<std::string, Column<T>>& columns,
                std::map<std::string, Column<T>>& out, Index index,
                Index entityCount)
{
  for (const auto& kv : columns) {
    Column<T> saved = kv.second.slice(index, entityCount);
    if (!saved.empty())
      out[kv.first] = saved;
  }
}

template <typename T>
void restoreDense(std::map<std::string, Column<T>>& columns,
                  const std::map<std::string, Column<T>>& saved, Index index,
                  Index entityCount)
{
  for (const auto& kv : saved) {
    auto it = columns.find(kv.first);
    if (it != columns.end())
      it->second.restore(index, kv.second, entityCount);
  }
}

} // namespace

void PropertyMap::removeEntry(Index index, Index entityCount)
{
  removeDense(m_doubles, index, entityCount, doubleSentinel);
  removeDense(m_ints, index, entityCount, intSentinel);
  removeDense(m_strings, index, entityCount, std::string());

  // Sparse matrices: remove the entry at index, re-key the last entry.
  Index lastIndex = entityCount - 1;
  for (auto& kv : m_matrices) {
    auto& col = kv.second;
    col.erase(index);
    if (index != lastIndex) {
      auto it = col.find(lastIndex);
      if (it != col.end()) {
        col[index] = std::move(it->second);
        col.erase(it);
      }
    }
  }
}

PropertyMap PropertyMap::slice(Index index, Index entityCount) const
{
  PropertyMap result;
  sliceDense(m_doubles, result.m_doubles, index, entityCount);
  sliceDense(m_ints, result.m_ints, index, entityCount);
  sliceDense(m_strings, result.m_strings, index, entityCount);
  for (const auto& kv : m_matrices) {
    auto it = kv.second.find(index);
    if (it != kv.second.end())
      result.m_matrices[kv.first][index] = it->second;
  }
  return result;
}

void PropertyMap::restore(Index index, const PropertyMap& saved,
                          Index entityCount)
{
  restoreDense(m_doubles, saved.m_doubles, index, entityCount);
  restoreDense(m_ints, saved.m_ints, index, entityCount);
  restoreDense(m_strings, saved.m_strings, index, entityCount);

  if (entityCount == 0)
    return;
  const Index lastIndex = entityCount - 1;
  for (auto& kv : m_matrices) {
    auto& col = kv.second;
    // removeEntry() erased index and then moved the last entity's matrix
    // there, so any matrix at index now belongs to the last entity.
    if (index != lastIndex) {
      auto it = col.find(index);
      if (it != col.end()) {
        col[lastIndex] = std::move(it->second);
        col.erase(index);
      }
    }
  }
  for (const auto& kv : saved.m_matrices) {
    for (const auto& entry : kv.second)
      m_matrices[kv.first][entry.first] = entry.second;
  }
}

void PropertyMap::eraseEntry(Index index, Index entityCount)
{
  for (auto& kv : m_doubles)
    kv.second.eraseEntry(index, entityCount);
  for (auto& kv : m_ints)
    kv.second.eraseEntry(index, entityCount);
  for (auto& kv : m_strings)
    kv.second.eraseEntry(index, entityCount);

  // Sparse matrices: drop the entry at index, re-key those above it.
  for (auto& kv : m_matrices) {
    std::unordered_map<Index, MatrixX> shifted;
    for (auto& entry : kv.second) {
      if (entry.first < index)
        shifted.emplace(entry.first, std::move(entry.second));
      else if (entry.first > index)
        shifted.emplace(entry.first - 1, std::move(entry.second));
    }
    kv.second = std::move(shifted);
  }
}

void PropertyMap::insertEntry(Index index, const PropertyMap& saved,
                              Index entityCount)
{
  // Every existing column shifts, including those @p saved has no entry for
  // (a column added after the slice, or an empty @p saved): the entity gets
  // the "unset" value there.
  auto insertDense = [index, entityCount](auto& columns, const auto& savedMap,
                                          const auto& sentinel) {
    for (auto& kv : columns) {
      auto it = savedMap.find(kv.first);
      if (it != savedMap.end())
        kv.second.insertEntry(index, it->second, entityCount);
      else
        kv.second.insertValue(index, sentinel, entityCount);
    }
  };
  insertDense(m_doubles, saved.m_doubles, doubleSentinel);
  insertDense(m_ints, saved.m_ints, intSentinel);
  insertDense(m_strings, saved.m_strings, std::string());

  for (auto& kv : m_matrices) {
    std::unordered_map<Index, MatrixX> shifted;
    for (auto& entry : kv.second) {
      shifted.emplace(entry.first >= index ? entry.first + 1 : entry.first,
                      std::move(entry.second));
    }
    kv.second = std::move(shifted);
  }
  for (const auto& kv : saved.m_matrices) {
    for (const auto& entry : kv.second)
      m_matrices[kv.first][entry.first] = entry.second;
  }
}

void PropertyMap::swapEntries(Index a, Index b)
{
  swapDense(m_doubles, a, b, doubleSentinel);
  swapDense(m_ints, a, b, intSentinel);
  swapDense(m_strings, a, b, std::string());

  // Sparse matrices: swap entries at a and b.
  for (auto& kv : m_matrices) {
    auto& col = kv.second;
    auto itA = col.find(a);
    auto itB = col.find(b);
    bool hasA = itA != col.end();
    bool hasB = itB != col.end();
    if (hasA && hasB) {
      std::swap(itA->second, itB->second);
    } else if (hasA) {
      col[b] = std::move(itA->second);
      col.erase(itA);
    } else if (hasB) {
      col[a] = std::move(itB->second);
      col.erase(itB);
    }
  }
}

void PropertyMap::clear()
{
  m_doubles.clear();
  m_ints.clear();
  m_strings.clear();
  m_matrices.clear();
}

bool PropertyMap::empty() const
{
  return m_doubles.empty() && m_ints.empty() && m_strings.empty() &&
         m_matrices.empty();
}

} // namespace Avogadro::Core
