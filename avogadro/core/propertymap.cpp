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
  auto& col = m_doubles[name];
  if (col.size() <= index)
    col.resize(index + 1, doubleSentinel);
  col[index] = value;
}

void PropertyMap::setInt(const std::string& name, Index index, int value)
{
  auto& col = m_ints[name];
  if (col.size() <= index)
    col.resize(index + 1, intSentinel);
  col[index] = value;
}

void PropertyMap::setString(const std::string& name, Index index,
                            const std::string& value)
{
  auto& col = m_strings[name];
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
  if (it == m_doubles.end() || index >= it->second.size())
    return std::nullopt;
  double val = it->second[index];
  if (std::isnan(val))
    return std::nullopt;
  return val;
}

std::optional<int> PropertyMap::getInt(const std::string& name,
                                       Index index) const
{
  auto it = m_ints.find(name);
  if (it == m_ints.end() || index >= it->second.size())
    return std::nullopt;
  int val = it->second[index];
  if (val == intSentinel)
    return std::nullopt;
  return val;
}

std::optional<std::string> PropertyMap::getString(const std::string& name,
                                                  Index index) const
{
  auto it = m_strings.find(name);
  if (it == m_strings.end() || index >= it->second.size())
    return std::nullopt;
  const std::string& val = it->second[index];
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
  m_doubles[name] = Array<double>(count, doubleSentinel);
}

void PropertyMap::createInts(const std::string& name, Index count)
{
  if (m_ints.find(name) != m_ints.end())
    return;
  m_ints[name] = Array<int>(count, intSentinel);
}

void PropertyMap::createStrings(const std::string& name, Index count)
{
  if (m_strings.find(name) != m_strings.end())
    return;
  m_strings[name] = Array<std::string>(count, std::string());
}

void PropertyMap::setDoubles(const std::string& name,
                             const Array<double>& values)
{
  m_doubles[name] = values;
}

const Array<double>& PropertyMap::doubles(const std::string& name) const
{
  static const Array<double> empty;
  auto it = m_doubles.find(name);
  if (it != m_doubles.end())
    return it->second;
  return empty;
}

void PropertyMap::setInts(const std::string& name, const Array<int>& values)
{
  m_ints[name] = values;
}

const Array<int>& PropertyMap::ints(const std::string& name) const
{
  static const Array<int> empty;
  auto it = m_ints.find(name);
  if (it != m_ints.end())
    return it->second;
  return empty;
}

void PropertyMap::setStrings(const std::string& name,
                             const Array<std::string>& values)
{
  m_strings[name] = values;
}

const Array<std::string>& PropertyMap::strings(const std::string& name) const
{
  static const Array<std::string> empty;
  auto it = m_strings.find(name);
  if (it != m_strings.end())
    return it->second;
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

void PropertyMap::addEntry()
{
  for (auto& kv : m_doubles)
    kv.second.push_back(doubleSentinel);
  for (auto& kv : m_ints)
    kv.second.push_back(intSentinel);
  for (auto& kv : m_strings)
    kv.second.push_back(std::string());
  // Sparse matrices: nothing to do on add.
}

namespace {

// A dense column can be shorter than the entity count: setDouble() and
// friends only grow it as far as the entity they were given, and an entity
// added afterwards has no entry. The entries it does have still belong to
// entities 0..size-1, so a swap or a swap-and-pop has to follow the same
// three cases as the optional arrays in Molecule (see swapAtomEntry() in
// molecule.cpp) rather than skip a short column, which would leave every
// value on the entity that now has its old index.
template <typename T>
void swapColumnEntries(Array<T>& column, Index a, Index b, const T& sentinel)
{
  const Index lo = a < b ? a : b;
  const Index hi = a < b ? b : a;
  if (column.size() <= lo)
    return; // neither entity has an entry
  if (column.size() <= hi)
    column.resize(hi + 1, sentinel); // only lo has one: it travels to hi
  std::swap(column[a], column[b]);
}

template <typename T>
void removeColumnEntry(Array<T>& column, Index index, Index entityCount,
                       const T& sentinel)
{
  // Entries past entityCount belong to no entity (the setters don't check
  // the index), so drop them and treat the column as full.
  if (column.size() > entityCount)
    column.resize(entityCount);
  if (column.size() == entityCount) {
    column.swapAndPop(index);
  } else if (index < column.size()) {
    // The entity swapped into index (the former last one) has no entry of
    // its own, so the stale value at index must not stay behind.
    column[index] = sentinel;
  }
}

} // namespace

void PropertyMap::removeEntry(Index index, Index entityCount)
{
  for (auto& kv : m_doubles)
    removeColumnEntry(kv.second, index, entityCount, doubleSentinel);
  for (auto& kv : m_ints)
    removeColumnEntry(kv.second, index, entityCount, intSentinel);
  for (auto& kv : m_strings)
    removeColumnEntry(kv.second, index, entityCount, std::string());

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

void PropertyMap::swapEntries(Index a, Index b, Index /*entityCount*/)
{
  for (auto& kv : m_doubles)
    swapColumnEntries(kv.second, a, b, doubleSentinel);
  for (auto& kv : m_ints)
    swapColumnEntries(kv.second, a, b, intSentinel);
  for (auto& kv : m_strings)
    swapColumnEntries(kv.second, a, b, std::string());

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
