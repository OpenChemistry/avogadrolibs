/// @file
/// @brief In-memory representation of a CIF (Crystallographic Information File) document.
///
/// This header defines the core data structures for parsing and manipulating CIF files.
/// It provides a document model that can represent both traditional CIF and mmCIF (macromolecular CIF)
/// formats, as well as alternative serializations like CIF-JSON or mmJSON.
/// The model consists of blocks, items (tag-value pairs or loops), and supports frame nesting.

// Copyright 2017 Global Phasing Ltd.
//
// struct Document that represents the CIF file (but can also be
// read from a different representation, such as CIF-JSON or mmJSON).

#ifndef GEMMI_CIFDOC_HPP_
#define GEMMI_CIFDOC_HPP_
#include "iterator.hpp"  // for StrideIter, IndirectIter
#include "atox.hpp"  // for string_to_int
#include "fail.hpp"  // for fail
#include "util.hpp"  // for starts_with, to_lower, cat
#include <cstddef>   // for size_t
#include <cstring>   // for memchr
#include <algorithm> // for move, find_if, all_of, min, rotate
#include <array>
#include <initializer_list>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(_MSC_VER)
#pragma warning(push)
// warning C4244: an integer type is converted to a smaller integer type
#pragma warning(disable: 4244)
// warning C4267: conversion from 'size_t' to 'type', possible loss of data
#pragma warning(disable: 4267)
#endif

namespace gemmi {
namespace cif {
using std::size_t;
using gemmi::fail;

/// @brief Discriminator for CIF items: single tag-value pairs, loops, or frames.
enum class ItemType : unsigned char {
  /// A single tag-value pair (e.g., `_cell.length_a  10.5`)
  Pair,
  /// A loop with tags (column headers) and values in row-major storage
  Loop,
  /// A save frame (nested block); used in CIF to define templates or additional metadata
  Frame,
  /// A comment item (prefix-preserved in output, not validated for syntax)
  Comment,
  /// Placeholder for a logically removed item; storage not reclaimed
  Erased,
};

inline uint8_t char_table(char c) {
  static const uint8_t table[256] = {
   // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
      0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 2, 0, 0, // 0
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1
      2, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, // 2
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, // 3
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, // 5
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, // 7
   // 128-255
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };
  return table[static_cast<unsigned char>(c)];
}

inline void assert_tag(const std::string& tag) {
  if (tag[0] != '_')
    fail("Tag should start with '_', got: " + tag);
}

inline void ensure_mmcif_category(std::string& cat) {
  if (cat[0] != '_')
    fail("Category should start with '_', got: " + cat);
  if (*(cat.end() - 1) != '.')
    cat += '.';
}

inline bool is_null(const std::string& value) {
  return value.size() == 1 && (value[0] == '?' || value[0] == '.');
}

inline std::string as_string(const std::string& value) {
  if (value.empty() || is_null(value))
    return "";
  if (value[0] == '"' || value[0] == '\'')
    return std::string(value.begin() + 1, value.end() - 1);
  if (value[0] == ';' && value.size() > 2 && *(value.end() - 2) == '\n') {
    bool crlf = *(value.end() - 3) == '\r';
    return std::string(value.begin() + 1, value.end() - (crlf ? 3 : 2));
  }
  return value;
}

inline std::string as_string(const std::string* value) {
  return value ? as_string(*value) : std::string();
}

inline char as_char(const std::string& value, char null) {
  if (is_null(value))
    return null;
  if (value.size() < 2)
    return value[0];
  const std::string s = as_string(value);
  if (s.size() < 2)
    return s[0];
  fail("Not a single character: " + value);
}

inline int as_int(const std::string& str) {
  return string_to_int(str, true);
}

inline int as_int(const std::string& str, int null) {
  return is_null(str) ? null : as_int(str);
}

// for use in templates (see also as_any() functions in numb.hpp)
inline int as_any(const std::string& s, int null) { return as_int(s, null); }
inline char as_any(const std::string& s, char null) { return as_char(s, null); }


using Pair = std::array<std::string, 2>;

// used only as arguments when creating Item
struct LoopArg {};
struct FrameArg { std::string str; };
struct CommentArg { std::string str; };

/// @brief A tabular loop structure: tags (column names) and flat row-major values.
///
/// In CIF syntax, a loop is a compact representation of a table with named columns:
/// ```
/// loop_
///   _category.tag1  _category.tag2  _category.tag3
///   value1a        value2a         value3a
///   value1b        value2b         value3b
/// ```
/// Internally, the tag names are stored in `tags` and all values are stored sequentially
/// in `values` using row-major layout: for N columns and M rows, `values.size() == N*M`,
/// and element at (row r, column c) is at index `r * N + c`.
struct Loop {
  /// Column header names (tags), typically with a common prefix (e.g., `_atom_site.`)
  std::vector<std::string> tags;
  /// All values in row-major order: consecutive `tags.size()` elements form one row.
  /// Invariant: `values.size() % tags.size() == 0`.
  std::vector<std::string> values;

  /// @brief Find a tag by case-insensitive match.
  /// @param lctag Tag name converted to lowercase.
  /// @return Column index (0-based) if found; -1 if not found.
  int find_tag_lc(const std::string& lctag) const {
    auto f = std::find_if(tags.begin(), tags.end(),
        [&lctag](const std::string& t) { return gemmi::iequal(t, lctag); });
    return f == tags.end() ? -1 : f - tags.begin();
  }
  /// @brief Find a tag by case-insensitive match.
  /// @param tag Tag name (converted to lowercase internally).
  /// @return Column index (0-based) if found; -1 if not found.
  int find_tag(const std::string& tag) const {
    return find_tag_lc(gemmi::to_lower(tag));
  }
  /// @brief Check if a tag exists (case-insensitive).
  bool has_tag(const std::string& tag) const { return find_tag(tag) != -1; }
  /// @brief Number of columns in this loop.
  size_t width() const { return tags.size(); }
  /// @brief Number of rows in this loop.
  size_t length() const { return values.size() / tags.size(); }

  /// @brief Direct access to a value by row and column index (row-major layout).
  /// @param row Row index (0-based).
  /// @param col Column index (0-based).
  /// @return Reference to the value at (row, col).
  std::string& val(size_t row, size_t col) { return values[row * tags.size() + col]; }
  /// @brief Const overload of val().
  const std::string& val(size_t row, size_t col) const {
    return const_cast<Loop*>(this)->val(row, col);
  }

  /// @brief Clear all tags and values from this loop.
  void clear() { tags.clear(); values.clear(); }

  /// @brief Insert values into the loop, optionally at a specific row position.
  /// @tparam T Container type with begin()/end() iterators (e.g., std::vector, std::initializer_list).
  /// @param new_values Container of strings to insert.
  /// @param pos Row position to insert at (-1 appends at end).
  template <typename T> void add_values(T new_values, int pos=-1) {
    auto it = values.end();
    if (pos >= 0 && pos * width() < values.size())
      it = values.begin() + pos * tags.size();
    values.insert(it, new_values.begin(), new_values.end());
  }
  /// @brief Overload for initializer_list.
  void add_values(std::initializer_list<std::string> new_values, int pos=-1) {
    add_values<std::initializer_list<std::string>>(new_values, pos);
  }
  /// @brief Add a complete row to the loop (must match column count).
  /// @tparam T Container with begin()/end() iterators.
  /// @param new_values Container of strings; size must equal `width()`.
  /// @param pos Row position to insert at (-1 appends at end).
  /// @throws std::runtime_error if new_values.size() != tags.size().
  template <typename T> void add_row(T new_values, int pos=-1) {
    if (new_values.size() != tags.size())
      fail("add_row(): wrong row length.");
    add_values<T>(new_values, pos);
  }
  /// @brief Overload for initializer_list.
  void add_row(std::initializer_list<std::string> new_values, int pos=-1) {
    add_row<std::initializer_list<std::string>>(new_values, pos);
  }
  /// @brief Add a comment prefix to the first value of a row, then add the row.
  /// @param ss Initializer list with comment string at index 0, then `width()` value strings.
  /// @throws std::runtime_error if ss.size() != tags.size() + 1.
  void add_comment_and_row(std::initializer_list<std::string> ss) {
    if (ss.size() != tags.size() + 1)
      fail("add_comment_and_row(): wrong row length.");
    std::vector<std::string> vec(ss.begin() + 1, ss.end());
    vec[0] = cat('#', *ss.begin(), '\n', vec[0]);
    add_row(vec);
  }
  /// @brief Remove the last row from the loop.
  /// @throws std::runtime_error if the loop is already empty.
  void pop_row() {
    if (values.size() < tags.size())
      fail("pop_row() called on empty Loop");
    values.resize(values.size() - tags.size());
  }

  /// @brief Move a row to a different position within the loop.
  /// @param old_pos Current row index (0-based); must be < length().
  /// @param new_pos Target row index (0-based); must be < length().
  void move_row(int old_pos, int new_pos) {
    size_t w = width();
    auto src = values.begin() + old_pos * w;
    auto dst = values.begin() + new_pos * w;
    if (src < dst)
      std::rotate(src, src+w, dst+w);
    else
      std::rotate(dst, src, src+w);
  }

  /// @brief Add new columns with an initial fill value.
  /// @param column_names Vector of new tag names (must start with '_').
  /// @param value String value to fill for all existing rows.
  /// @param pos Column position to insert at (-1 appends at end).
  void add_columns(const std::vector<std::string>& column_names,
                   const std::string& value, int pos=-1) {
    for (const std::string& name : column_names)
      assert_tag(name);
    size_t old_width = tags.size();
    size_t len = length();
    size_t upos = std::min((size_t)pos, old_width);
    tags.insert(tags.begin() + upos, column_names.begin(), column_names.end());
    vector_insert_columns(values, old_width, len, column_names.size(), upos, value);
  }

  /// @brief Remove a column by tag name.
  /// @param column_name Tag to remove (case-insensitive search).
  /// @throws std::runtime_error if tag not found.
  void remove_column(const std::string& column_name) {
    int n = find_tag(column_name);
    if (n == -1)
      fail("remove_column(): tag not found: " + column_name);
    remove_column_at(n);
  }

  /// @brief Remove a column by index.
  /// @param n Column index; must be < tags.size().
  void remove_column_at(size_t n) {
    tags.erase(tags.begin() + n);
    vector_remove_column(values, tags.size(), n);
  }

  /// @brief Replace all values with columns from a vector of column vectors.
  /// @param columns Vector of columns; size must equal width(), each column must equal length().
  void set_all_values(std::vector<std::vector<std::string>> columns);

  /// @brief Extract the common prefix from all tags in this loop.
  /// @return Longest prefix that all tags share (case-insensitive).
  std::string common_prefix() const {
    if (tags.empty())
      return {};
    size_t len = tags[0].size();
    for (auto it = tags.begin() + 1; it != tags.end(); ++it)
      for (size_t n = 0; n != len; ++n)
        if (!isame(tags[0][n], (*it)[n])) {
          len = n;
          break;
        }
    return tags[0].substr(0, len);
  }
};


struct Item;
struct Block;

/// @brief A view into a single column of a Loop, or a single Pair value.
///
/// Provides array-like access to a sequence of values from either a loop column or a pair value.
/// Acts as both a reference (can be modified through operator[]) and an iterable container.
class Column {
public:
  /// @brief Construct an empty/null column.
  Column() : item_(nullptr) {}
  /// @brief Construct a column view for a specific item and column index.
  /// @param item Pointer to an Item (must be Loop or Pair type).
  /// @param col Column index; for Loop, this is the column position; for Pair, should be 0.
  Column(Item* item, size_t col) : item_(item), col_(col) {}
  /// @brief Iterator type for strided traversal of column values.
  using iterator = StrideIter<std::string>;
  /// @brief Begin iterator; provides access to the first value in the column.
  iterator begin();
  /// @brief End iterator; one-past-the-last value.
  iterator end();
  /// @brief Const iterator type.
  using const_iterator = StrideIter<const std::string>;
  /// @brief Const begin iterator.
  const_iterator begin() const { return const_cast<Column*>(this)->begin(); }
  /// @brief Const end iterator.
  const_iterator end() const { return const_cast<Column*>(this)->end(); }

  /// @brief Get the underlying Loop, if this column comes from a Loop item; nullptr otherwise.
  Loop* get_loop() const;
  /// @brief Get the tag (column header) string for this column.
  /// @return Pointer to the tag string (valid as long as the Item is alive).
  std::string* get_tag();
  /// @brief Const overload of get_tag().
  const std::string* get_tag() const {
    return const_cast<Column*>(this)->get_tag();
  }
  /// @brief Number of values in this column.
  /// @return Loop length if from a Loop; 1 if from a Pair; 0 if null.
  int length() const {
    if (const Loop* loop = get_loop())
      return loop->length();
    return item_ ? 1 : 0;
  }
  /// @brief Check if this column is valid (not null).
  explicit operator bool() const { return item_ != nullptr ; }
  /// @brief Access a value by index (0-based; for Pair, only index 0 is valid).
  std::string& operator[](int n);
  /// @brief Safe access with bounds checking and negative indexing support.
  /// @param n Index (negative indices count from end).
  /// @return Reference to the value.
  /// @throws std::out_of_range if index is out of bounds.
  std::string& at(int n) {
    if (n < 0)
      n += length();
    if (n < 0 || n >= length())
      throw std::out_of_range("Cannot access element " + std::to_string(n) +
          " in Column with length " + std::to_string(length()));
    return operator[](n);
  }
  /// @brief Const overload of at().
  const std::string& at(int n) const {
    return const_cast<Column*>(this)->at(n);
  }

  /// @brief Get a CIF-unquoted string value (removes quotes/semicolons).
  std::string str(int n) const { return as_string(at(n)); }
  /// @brief Get const pointer to the underlying Item.
  const Item* item() const { return item_; }
  /// @brief Get mutable pointer to the underlying Item.
  Item* item() { return item_; }
  /// @brief Get the column index within the Loop (or 0 for Pair).
  size_t col() const { return col_; }

  /// @brief Erase this column from its item (removes from Loop or erases Pair).
  void erase();

private:
  Item* item_;           ///< Pointer to the Item (Loop or Pair).
  size_t col_;           ///< Column index in the Loop, or 0 for Pair.
};

/// @brief A unified view of data as either a loop (multiple rows) or pairs (single row).
///
/// Some CIF data can be represented either way:
/// - As a loop with multiple rows (efficient for large tables)
/// - As separate tag-value pairs (equivalent to a loop with one row)
///
/// This struct abstracts both representations to provide uniform access through Row objects.
/// It internally tracks column mappings and optimizes for the loop case.
struct Table {
  /// @brief Pointer to the Loop Item, or nullptr if data is in pairs.
  Item* loop_item;
  /// @brief Reference to the Block containing the items.
  Block& bloc;
  /// @brief Column position mappings: for each query column, the position in loop/pairs.
  /// Negative position (-1) means the column is optional and absent.
  std::vector<int> positions;
  /// @brief Length of the common tag prefix (e.g., `_atom_site.` length).
  size_t prefix_length;

  /// @brief A single row of the table, providing key-value access to columns.
  struct Row {
    /// @brief Reference to the parent Table.
    Table& tab;
    /// @brief Row index (-1 represents the tag row itself).
    int row_index;

    /// @brief Unsafe access: position must be valid (>=0).
    std::string& value_at_unsafe(int pos);
    /// @brief Safe access by position; throws if position is -1 (optional column absent).
    std::string& value_at(int pos) {
      if (pos == -1)
        throw std::out_of_range("Cannot access missing optional tag.");
      return value_at_unsafe(pos);
    }
    /// @brief Const overload of value_at().
    const std::string& value_at(int pos) const {
      return const_cast<Row*>(this)->value_at(pos);
    }

    /// @brief Access by column index in the table query (with bounds checking).
    std::string& at(int n) {
      return value_at(tab.positions.at(n < 0 ? n + size() : n));
    }
    /// @brief Const overload of at().
    const std::string& at(int n) const { return const_cast<Row*>(this)->at(n); }

    /// @brief Unchecked access by column index.
    std::string& operator[](size_t n);
    /// @brief Const overload.
    const std::string& operator[](size_t n) const {
      return const_cast<Row*>(this)->operator[](n);
    }

    /// @brief Pointer-based access to optional columns (nullptr if absent).
    std::string* ptr_at(int n) {
      int pos = tab.positions.at(n < 0 ? n + size() : n);
      return pos >= 0 ? &value_at(pos) : nullptr;
    }
    /// @brief Const overload of ptr_at().
    const std::string* ptr_at(int n) const {
      return const_cast<Row*>(this)->ptr_at(n);
    }

    /// @brief Check if a column is present.
    bool has(size_t n) const { return tab.positions.at(n) >= 0; }
    /// @brief Check if a column is present and has a non-null value.
    bool has2(size_t n) const { return has(n) && !cif::is_null(operator[](n)); }

    /// @brief Return the first non-null value among two columns, or a null placeholder.
    const std::string& one_of(size_t n1, size_t n2) const {
      static const std::string nul(1, '.');
      if (has2(n1))
        return operator[](n1);
      if (has(n2))
        return operator[](n2);
      return nul;
    }

    /// @brief Number of columns in the table query.
    size_t size() const { return tab.width(); }

    /// @brief Get a CIF-unquoted string value.
    std::string str(int n) const { return as_string(at(n)); }

    /// @brief Iterator type for traversing columns in this row.
    using iterator = IndirectIter<Row, std::string>;
    /// @brief Const iterator type.
    using const_iterator = IndirectIter<const Row, const std::string>;
    /// @brief Begin iterator.
    iterator begin() { return iterator({this, tab.positions.begin()}); }
    /// @brief End iterator.
    iterator end() { return iterator({this, tab.positions.end()}); }
    /// @brief Const begin iterator.
    const_iterator begin() const {
      return const_iterator({this, tab.positions.begin()});
    }
    /// @brief Const end iterator.
    const_iterator end() const {
      return const_iterator({this, tab.positions.end()});
    }
  };

  /// @brief Get the underlying Loop, if this table is loop-based.
  Loop* get_loop();
  /// @brief Check if this table is valid (has at least one column).
  bool ok() const { return !positions.empty(); }
  /// @brief Number of columns in the table query.
  size_t width() const { return positions.size(); }
  /// @brief Number of rows in this table.
  size_t length() const;
  /// @brief Alias for length().
  size_t size() const { return length(); }
  /// @brief Check if column n is present (not -1).
  bool has_column(int n) const { return ok() && positions.at(n) >= 0; }
  /// @brief Access the tag row (row_index == -1).
  Row tags() { return Row{*this, -1}; }
  /// @brief Access a data row by index.
  Row operator[](int n) { return Row{*this, n}; }

  /// @brief Validate and normalize a row index (supports negative indexing).
  /// @param n Index to check (modified in-place).
  /// @throws std::out_of_range if index is invalid.
  void at_check(int& n) const {
    if (n < 0)
      n += length();
    if (n < 0 || static_cast<size_t>(n) >= length())
      throw std::out_of_range("No row with index " + std::to_string(n));
  }
  /// @brief Safe row access with bounds checking.
  Row at(int n) {
    at_check(n);
    return (*this)[n];
  }

  /// @brief Get the single row of a one-row table.
  /// @return The first (and only) row.
  /// @throws std::runtime_error if table has != 1 row.
  Row one() {
    if (length() != 1)
      fail("Expected one value, found " + std::to_string(length()));
    return (*this)[0];
  }

  /// @brief Get the common category prefix for this table (e.g., `_atom_site`).
  std::string get_prefix() const {
    for (int pos : positions)
      if (pos >= 0)
        return const_cast<Table*>(this)->tags()
               .value_at(pos).substr(0, prefix_length);
    fail("The table has no columns.");
  }

  /// @brief Find the first row where the first column matches a value.
  /// @param s String value to search for (compared with as_string unquoting).
  /// @return The matching row.
  /// @throws std::runtime_error if no row matches.
  Row find_row(const std::string& s);

  /// @brief Append a row with values matching the table columns.
  /// @tparam T Container type with begin()/end().
  /// @param new_values Container of strings; size must equal width().
  template <typename T> void append_row(const T& new_values);
  /// @brief Overload for initializer_list.
  void append_row(std::initializer_list<std::string> new_values) {
    append_row<std::initializer_list<std::string>>(new_values);
  }
  /// @brief Remove a single row.
  void remove_row(int row_index) { remove_rows(row_index, row_index+1); }
  /// @brief Remove rows [start, end).
  void remove_rows(int start, int end);
  /// @brief Create a Column view for a position.
  Column column_at_pos(int pos);
  /// @brief Get a Column view by table column index.
  /// @param n Column index in the query.
  /// @throws std::runtime_error if the column is absent (position -1).
  Column column(int n) {
    int pos = positions.at(n);
    if (pos == -1)
      fail("Cannot access absent column");
    return column_at_pos(pos);
  }

  /// @brief Move a row to a different position.
  void move_row(int old_pos, int new_pos) {
    at_check(old_pos);
    at_check(new_pos);
    if (Loop* loop = get_loop())
      loop->move_row(old_pos, new_pos);
  }

  /// @brief Find a column by tag name (supports prefix matching).
  /// @param tag Column name to search for (case-insensitive).
  /// @return Position of the matching column.
  /// @throws std::runtime_error if tag not found.
  int find_column_position(const std::string& tag) const {
    std::string lctag = gemmi::to_lower(tag);
    Row tag_row = const_cast<Table*>(this)->tags();
    for (int pos : positions) {
      const std::string& v = tag_row.value_at_unsafe(pos);
      if (v.length() == lctag.length() ? gemmi::iequal(v, lctag)
                                       : gemmi::iequal_from(v, prefix_length, lctag))
        return pos;
    }
    fail("Column name not found: " + tag);
  }

  /// @brief Get a Column view by tag name.
  Column find_column(const std::string& tag) {
    return column_at_pos(find_column_position(tag));
  }

  /// @brief Erase this table (remove all its items from the block).
  void erase();

  /// @brief Ensure data is in loop form (convert from pairs if needed).
  void ensure_loop();

  /// @brief Iterator for range-based for loops over rows.
  struct iterator {
    Table& parent;
    int index;
    void operator++() { index++; }
    bool operator==(const iterator& o) const { return index == o.index; }
    bool operator!=(const iterator& o) const { return index != o.index; }
    Row operator*() { return parent[index]; }
    const std::string& get(int n) const { return parent[index].at(n); }
  };
  /// @brief Begin iterator for rows.
  iterator begin() { return iterator{*this, 0}; }
  /// @brief End iterator for rows.
  iterator end() { return iterator{*this, (int)length()}; }
};

/// @brief A CIF data block, containing tags (pairs), loops, and nested frames.
///
/// In CIF syntax, a block starts with `data_blockname` and contains items:
/// - Tag-value pairs: `_tag value`
/// - Loops: `loop_ _tag1 _tag2 ... value1a value2a value1b value2b ...`
/// - Frames: `save_framename ... save_`
///
/// Blocks are case-insensitive for tag lookup (but case is preserved in output).
struct Block {
  /// @brief Block name (e.g., "structure" in `data_structure`).
  std::string name;
  /// @brief Items in this block (pairs, loops, frames, comments).
  std::vector<Item> items;

  /// @brief Construct a named block.
  explicit Block(const std::string& name_);
  /// @brief Construct an unnamed block.
  Block();

  /// @brief Swap contents with another block.
  void swap(Block& o) noexcept { name.swap(o.name); items.swap(o.items); }
  // access functions
  /// @brief Find an Item that is a tag-value pair by tag name.
  /// @param tag Tag to search for (case-insensitive).
  /// @return Pointer to the Item, or nullptr if not found or not a Pair.
  const Item* find_pair_item(const std::string& tag) const;
  /// @brief Find a tag-value pair (Pair).
  /// @param tag Tag to search for (case-insensitive).
  /// @return Pointer to the Pair, or nullptr if not found.
  const Pair* find_pair(const std::string& tag) const;
  /// @brief Find a loop containing a tag and get a Column view.
  /// @param tag Tag to search for (case-insensitive).
  /// @return Column view if found and item is a Loop; empty Column otherwise.
  Column find_loop(const std::string& tag);
  /// @brief Find an Item that is a loop containing a tag.
  /// @param tag Tag to search for (case-insensitive).
  /// @return Pointer to the Item, or nullptr if not found.
  const Item* find_loop_item(const std::string& tag) const;
  /// @brief Find a single value (from Pair or first row of Loop with single column).
  /// @param tag Tag to search for (case-insensitive).
  /// @return Pointer to the value string, or nullptr if not found.
  const std::string* find_value(const std::string& tag) const;
  /// @brief Find all values with a tag (Column from Loop or Pair).
  /// @param tag Tag to search for (case-insensitive).
  /// @return Column view (empty if not found).
  Column find_values(const std::string& tag);
  /// @brief Check if a tag exists in this block.
  bool has_tag(const std::string& tag) const {
    return const_cast<Block*>(this)->find_values(tag).item() != nullptr;
  }
  /// @brief Check if a tag exists and has at least one non-null value.
  bool has_any_value(const std::string& tag) const {
    Column c = const_cast<Block*>(this)->find_values(tag);
    return c.item() != nullptr && !std::all_of(c.begin(), c.end(), is_null);
  }
  /// @brief Find a table of values with specified tags (required tags).
  /// @param prefix Common tag prefix (e.g., `_atom_site`).
  /// @param tags Tags to search for (no '?' prefix; all required).
  /// @return Table view (ok() == false if not all tags found).
  Table find(const std::string& prefix,
             const std::vector<std::string>& tags);
  /// @brief Overload without prefix.
  Table find(const std::vector<std::string>& tags) { return find({}, tags); }
  /// @brief Find a table with optional tags (all columns attempted).
  /// @param prefix Common tag prefix.
  /// @param tags Tags to search for; position -1 if not found.
  /// @return Table view.
  Table find_any(const std::string& prefix,
                 const std::vector<std::string>& tags);
  /// @brief Find a table, creating it if not found.
  /// @param prefix Common tag prefix.
  /// @param tags Tags; all are created as a new loop if not found.
  /// @return Table view (ok() == true).
  Table find_or_add(const std::string& prefix, std::vector<std::string> tags) {
    Table t = find(prefix, tags);
    if (!t.ok()) {
      for (int i = 0; i != (int) tags.size(); ++i)
        t.positions.push_back(i);
      Table tab = find_any(prefix, tags);
      t.loop_item = &setup_loop_item(std::move(tab), prefix, std::move(tags));
    }
    return t;
  }
  /// @brief Find a nested frame (save block) by name.
  /// @param name Frame name (case-insensitive).
  /// @return Pointer to the frame Block, or nullptr if not found.
  Block* find_frame(std::string name);
  /// @brief Convert a Loop Item to a Table view.
  Table item_as_table(Item& item);

  /// @brief Get the index of an item containing a tag.
  /// @param tag Tag to search for (case-insensitive).
  /// @return Index in the items vector.
  /// @throws std::runtime_error if tag not found.
  size_t get_index(const std::string& tag) const;

  // modifying functions
  /// @brief Set or update a tag-value pair.
  /// @param tag Tag name (case-insensitive for lookup, but case is updated if tag is added).
  /// @param value Value to set.
  void set_pair(const std::string& tag, const std::string& value);

  /// @brief Initialize or get a loop for specified tags.
  /// @param prefix Common tag prefix.
  /// @param tags Column names (prefix added automatically).
  /// @return Reference to the Loop (newly created if needed).
  Loop& init_loop(const std::string& prefix, std::vector<std::string> tags) {
    Table tab = find_any(prefix, tags);
    return setup_loop(std::move(tab), prefix, std::move(tags));
  }

  /// @brief Move an item to a different position.
  /// @param old_pos Current position (supports negative indexing).
  /// @param new_pos Target position (supports negative indexing).
  void move_item(int old_pos, int new_pos);

  // mmCIF specific functions
  /// @brief Get all category prefixes in mmCIF format (ending with '.').
  std::vector<std::string> get_mmcif_category_names() const;
  /// @brief Find a category (all tags starting with prefix).
  /// @param cat Category prefix (e.g., `_atom_site`; '.' is added if missing).
  /// @return Table view with all matching tags.
  Table find_mmcif_category(std::string cat);
  /// @brief Check if an mmCIF category exists.
  /// @param cat Category prefix.
  bool has_mmcif_category(std::string cat) const;

  /// @brief Initialize an mmCIF category loop.
  /// @param cat Category prefix.
  /// @param tags Column names (category prefix added automatically).
  /// @return Reference to the Loop.
  Loop& init_mmcif_loop(std::string cat, std::vector<std::string> tags) {
    ensure_mmcif_category(cat);  // modifies cat
    return setup_loop(find_mmcif_category(cat), cat, std::move(tags));
  }

private:
  Item& setup_loop_item(Table&& tab, const std::string& prefix,
                        std::vector<std::string>&& tags);
  Loop& setup_loop(Table&& tab, const std::string& prefix,
                   std::vector<std::string>&& tags);
};


/// @brief A single item in a CIF block: a pair, loop, frame, comment, or erased marker.
///
/// Uses a discriminated union (tagged with ItemType) to store different data types.
/// For a Pair, stores tag and value. For a Loop, stores tags and values vectors.
/// For a Frame, stores a nested Block.
struct Item {
  /// @brief The type of item (discriminator for the union).
  ItemType type;
  /// @brief Source line number where this item was parsed (or -1 if not from parsing).
  int line_number = -1;
  /// @brief Union storing the actual data (only one is valid based on type).
  union {
    /// @brief For Pair items: [tag, value].
    Pair pair;
    /// @brief For Loop items: tags and values.
    Loop loop;
    /// @brief For Frame items: nested save frame Block.
    Block frame;
  };

  /// @brief Construct an erased (empty) item.
  Item() : type(ItemType::Erased) {}
  /// @brief Construct a Loop item.
  explicit Item(LoopArg)
    : type{ItemType::Loop}, loop{} {}
  /// @brief Construct a Pair with a tag (value empty).
  explicit Item(std::string&& t)
    : type{ItemType::Pair}, pair{{std::move(t), std::string()}} {}
  /// @brief Construct a Pair with tag and value.
  Item(const std::string& t, const std::string& v)
    : type{ItemType::Pair}, pair{{t, v}} {}
  /// @brief Construct a Frame from a FrameArg.
  explicit Item(FrameArg&& frame_arg)
    : type{ItemType::Frame}, frame(frame_arg.str) {}
  /// @brief Construct a Comment from a CommentArg.
  explicit Item(CommentArg&& comment)
    : type{ItemType::Comment}, pair{{std::string(), std::move(comment.str)}} {}

  /// @brief Move constructor.
  Item(Item&& o) noexcept
      : type(o.type), line_number(o.line_number) {
    move_value(std::move(o));
  }
  /// @brief Copy constructor.
  Item(const Item& o)
      : type(o.type), line_number(o.line_number) {
    copy_value(o);
  }

  /// @brief Assignment operator (move-based).
  Item& operator=(Item o) { set_value(std::move(o)); return *this; }

  /// @brief Destructor (calls destruct on the active union member).
  ~Item() { destruct(); }

  /// @brief Mark this item as erased without freeing underlying storage.
  /// Changes type to Erased; the union memory is left as-is.
  void erase() {
    destruct();
    type = ItemType::Erased;
  }

  /// @brief Check if this item's tag(s) start with a prefix (case-insensitive).
  /// @param prefix Prefix to match (should be lowercase).
  /// @return True if the first tag starts with prefix.
  bool has_prefix(const std::string& prefix) const {
    return (type == ItemType::Pair && gemmi::istarts_with(pair[0], prefix)) ||
           (type == ItemType::Loop && !loop.tags.empty() &&
            gemmi::istarts_with(loop.tags[0], prefix));
  }

  /// @brief Replace this item's value with another item (may change type).
  void set_value(Item&& o) {
    if (type == o.type) {
      switch (type) {
        case ItemType::Pair: pair = std::move(o.pair); break;
        case ItemType::Loop: loop = std::move(o.loop); break;
        case ItemType::Frame: frame = std::move(o.frame); break;
        case ItemType::Comment: pair = std::move(o.pair); break;
        case ItemType::Erased: break;
      }
    } else {
      destruct();
      type = o.type;
      move_value(std::move(o));
    }
  }

private:
  void destruct() {
    switch (type) {
      case ItemType::Pair: pair.~Pair(); break;
      case ItemType::Loop: loop.~Loop(); break;
      case ItemType::Frame: frame.~Block(); break;
      case ItemType::Comment: pair.~Pair(); break;
      case ItemType::Erased: break;
    }
  }

  void copy_value(const Item& o) {
    if (o.type == ItemType::Pair || o.type == ItemType::Comment)
      new (&pair) Pair(o.pair);
    else if (o.type == ItemType::Loop)
      new (&loop) Loop(o.loop);
    else if (o.type == ItemType::Frame)
      new (&frame) Block(o.frame);
  }

  void move_value(Item&& o) {
    if (o.type == ItemType::Pair || o.type == ItemType::Comment)
      new (&pair) Pair(std::move(o.pair));
    else if (o.type == ItemType::Loop)
      new (&loop) Loop(std::move(o.loop));
    else if (o.type == ItemType::Frame)
      new (&frame) Block(std::move(o.frame));
  }
};


// ItemSpan is used to add tag-value pairs next to the same category tags.
struct ItemSpan {
  ItemSpan(std::vector<Item>& items)
      : items_(items), begin_(0), end_(items.size()) {}
  ItemSpan(std::vector<Item>& items, std::string prefix)
      : ItemSpan(items) {
    assert_tag(prefix);
    prefix = gemmi::to_lower(prefix);
    while (begin_ != end_ && !items_[begin_].has_prefix(prefix))
      ++begin_;
    if (begin_ != end_)
      while (end_-1 != begin_ && !items_[end_-1].has_prefix(prefix))
        --end_;
  }
  void set_pair(const std::string& tag, const std::string& value) {
    assert_tag(tag);
    std::string lctag = gemmi::to_lower(tag);
    auto end = items_.begin() + end_;
    for (auto i = items_.begin() + begin_; i != end; ++i) {
      if (i->type == ItemType::Pair && gemmi::iequal(i->pair[0], lctag)) {
        i->pair[0] = tag;  // if letter case differs, the tag changes
        i->pair[1] = value;
        return;
      }
      if (i->type == ItemType::Loop && i->loop.find_tag_lc(lctag) != -1) {
        i->set_value(Item(tag, value));
        return;
      }
    }
    items_.emplace(end, tag, value);
    ++end_;
  }
private:
  std::vector<Item>& items_;
  size_t begin_, end_;  // iterators would be invalidated by emplace()
};


inline void Loop::set_all_values(std::vector<std::vector<std::string>> columns){
  size_t w = columns.size();
  if (w != width())
    fail(cat("set_all_values(): expected ", width(), " columns, got ", w));
  if (w == 0)
    return;
  size_t h = columns[0].size();
  for (auto& col : columns)
    if (col.size() != h)
      fail("set_all_values(): all columns must have the same length");
  values.resize(w * h);
  for (size_t i = 0; i != h; ++i)
    for (size_t j = 0; j != w; ++j)
      values[w * i + j] = std::move(columns[j][i]);
}

inline std::string* Column::get_tag() {
  if (!item_)
    return nullptr;
  if (Loop* loop = get_loop())
    return &loop->tags.at(col_);
  return &item_->pair[0];
}

inline void Column::erase() {
  if (Loop* loop = get_loop())
    loop->remove_column_at(col_);
  else if (item_)
    item_->erase();
}

inline Loop* Column::get_loop() const {
  return item_ && item_->type == ItemType::Loop ? &item_->loop : nullptr;
}
inline Column::iterator Column::begin() {
  if (Loop* loop = get_loop())
    return iterator({loop->values.data(), col_, (unsigned) loop->width()});
  if (item_ && item_->type == ItemType::Pair)
    return iterator({&item_->pair[1], 0, 1});
  return iterator();
}

inline Column::iterator Column::end() {
  if (Loop* loop = get_loop())
    return iterator({loop->values.data() + loop->values.size(),
                    col_, (unsigned) loop->width()});
  if (item_ && item_->type == ItemType::Pair)
    return iterator({&item_->pair[1] + 1, 0, 1});
  return iterator();
}

inline std::string& Column::operator[](int n) {
  if (Loop* loop = get_loop())
    return loop->values[n * loop->width() + col_];
  return item_->pair[1];
}

inline std::string& Table::Row::operator[](size_t n) {
  int pos = tab.positions[n];
  if (Loop* loop = tab.get_loop()) {
    if (row_index == -1) // tags
      return loop->tags[pos];
    return loop->values[loop->width() * row_index + pos];
  }
  return tab.bloc.items[pos].pair[row_index == -1 ? 0 : 1];
}

inline std::string& Table::Row::value_at_unsafe(int pos) {
  Loop* loop = tab.get_loop();
  if (row_index == -1) { // tags
    if (loop)
      return loop->tags.at(pos);
    return tab.bloc.items[pos].pair[0];
  }
  if (loop)
    return loop->values.at(loop->width() * row_index + pos);
  return tab.bloc.items[pos].pair[1];
}

inline Loop* Table::get_loop() {  // NOLINT(readability-make-member-function-const)
  return loop_item ? &loop_item->loop : nullptr;
}

inline size_t Table::length() const {
  return loop_item ? loop_item->loop.length() : (positions.empty() ? 0 : 1);
}

inline Table::Row Table::find_row(const std::string& s) {
  int pos = positions.at(0);
  if (const Loop* loop = get_loop()) {
    for (size_t i = 0; i < loop->values.size(); i += loop->width())
      if (as_string(loop->values[i + pos]) == s)
        return Row{*this, static_cast<int>(i / loop->width())};
  } else if (as_string(bloc.items[pos].pair[1]) == s) {
    return Row{*this, 0};
  }
  fail("Not found in " + *column_at_pos(pos).get_tag() + ": " + s);
}

template <typename T> void Table::append_row(const T& new_values) {
  if (!ok())
    fail("append_row(): table not found");
  if (new_values.size() != width())
    fail("append_row(): wrong row length");
  if (!loop_item)
    fail("append_row(): data is not in loop, call ensure_loop() first");
  Loop& loop = loop_item->loop;
  size_t cur_size = loop.values.size();
  loop.values.resize(cur_size + loop.width(), ".");
  int n = 0;
  for (const auto& value : new_values)
    loop.values[cur_size + positions[n++]] = value;
}

inline void Table::remove_rows(int start, int end) {
  if (!ok())
    // this function is used mostly through remove_row()
    fail("remove_row(): table not found");
  ensure_loop();  // should we fail instead if we have pairs?
  Loop& loop = loop_item->loop;
  size_t start_pos = start * loop.width();
  size_t end_pos = end * loop.width();
  if (start_pos >= end_pos || end_pos > loop.values.size())
    throw std::out_of_range("remove_row(): invalid index");
  loop.values.erase(loop.values.begin() + start_pos,
                    loop.values.begin() + end_pos);
}

inline Column Table::column_at_pos(int pos) {
  if (loop_item)
    return Column(loop_item, pos);
  return Column(&bloc.items[pos], 0);
}

inline void Table::erase() {
  if (loop_item) {
    loop_item->erase();
    loop_item = nullptr;
  } else {
    for (int pos : positions)
      if (pos >= 0)
        bloc.items[pos].erase();
  }
  positions.clear();
}

inline void Table::ensure_loop() {
  if (loop_item)
    return;
  Item new_item(LoopArg{});
  new_item.loop.tags.resize(positions.size());
  new_item.loop.values.resize(positions.size());
  loop_item = &bloc.items.at(positions[0]);
  for (size_t i = 0; i != positions.size(); ++i) {
    Item& item = bloc.items[positions[i]];
    new_item.loop.tags[i].swap(item.pair[0]);
    new_item.loop.values[i].swap(item.pair[1]);
    item.erase();
    positions[i] = i;
  }
  loop_item->set_value(std::move(new_item));
}

inline Block::Block(const std::string& name_) : name(name_) {}
inline Block::Block() {}

inline const Item* Block::find_pair_item(const std::string& tag) const {
  std::string lctag = gemmi::to_lower(tag);
  for (const Item& i : items)
    if (i.type == ItemType::Pair && gemmi::iequal(i.pair[0], lctag))
      return &i;
  return nullptr;
}

inline const Pair* Block::find_pair(const std::string& tag) const {
  const Item* item = find_pair_item(tag);
  return item ? &item->pair : nullptr;
}

inline Column Block::find_loop(const std::string& tag) {
  Column c = find_values(tag);
  return c.item() && c.item()->type == ItemType::Loop ? c : Column();
}

inline const Item* Block::find_loop_item(const std::string& tag) const {
  for (const Item& i : items)
    if (i.type == ItemType::Loop && i.loop.find_tag_lc(tag) != -1)
      return &i;
  return nullptr;
}

inline const std::string* Block::find_value(const std::string& tag) const {
  std::string lctag = gemmi::to_lower(tag);
  for (const Item& i : items)
    if (i.type == ItemType::Pair && gemmi::iequal(i.pair[0], lctag))
      return &i.pair[1];
  for (const Item& i : items)
    if (i.type == ItemType::Loop) {
      int pos = i.loop.find_tag_lc(lctag);
      if (pos != -1 && i.loop.tags.size() == i.loop.values.size())
        return &i.loop.values[pos];
    }
  return nullptr;
}

inline Column Block::find_values(const std::string& tag) {
  std::string lctag = gemmi::to_lower(tag);
  for (Item& i : items)
    if (i.type == ItemType::Loop) {
      int pos = i.loop.find_tag_lc(lctag);
      if (pos != -1)
        return Column{&i, static_cast<size_t>(pos)};
    } else if (i.type == ItemType::Pair) {
      if (gemmi::iequal(i.pair[0], lctag))
        return Column{&i, 0};
    }
  return Column{nullptr, 0};
}

inline Block* Block::find_frame(std::string frame_name) {
  frame_name = gemmi::to_lower(frame_name);
  for (Item& i : items)
    if (i.type == ItemType::Frame && gemmi::iequal(i.frame.name, frame_name))
      return &i.frame;
  return nullptr;
}

inline Table Block::item_as_table(Item& item) {
  if (item.type != ItemType::Loop)
    fail("item_as_table: item is not Loop");
  std::vector<int> indices(item.loop.tags.size());
  for (size_t j = 0; j != indices.size(); ++j)
    indices[j] = (int) j;
  return Table{&item, *this, indices, 0};
}

inline size_t Block::get_index(const std::string& tag) const {
  std::string lctag = gemmi::to_lower(tag);
  for (size_t i = 0; i != items.size(); ++i) {
    const Item& item = items[i];
    if ((item.type == ItemType::Pair && gemmi::iequal(item.pair[0], lctag)) ||
        (item.type == ItemType::Loop && item.loop.find_tag_lc(lctag) != -1))
      return i;
  }
  fail(tag + " not found in block");
}

inline void Block::set_pair(const std::string& tag, const std::string& value) {
  ItemSpan(items).set_pair(tag, value);
}

inline void Block::move_item(int old_pos, int new_pos) {
  if (old_pos < 0)
    old_pos += items.size();
  if ((size_t) old_pos >= items.size())
    fail("move_item: old_pos out of range");
  if (new_pos < 0)
    new_pos += items.size();
  if ((size_t) new_pos >= items.size())
    fail("move_item: new_pos out of range");
  auto src = items.begin() + old_pos;
  auto dst = items.begin() + new_pos;
  if (src < dst)
    std::rotate(src, src+1, dst+1);
  else
    std::rotate(dst, src, src+1);
}

inline std::vector<std::string> Block::get_mmcif_category_names() const {
  std::vector<std::string> cats;
  for (const Item& item : items) {
    const std::string* tag = nullptr;
    if (item.type == ItemType::Pair)
      tag = &item.pair[0];
    else if (item.type == ItemType::Loop && !item.loop.tags.empty())
      tag = &item.loop.tags[0];
    if (tag)
      for (auto j = cats.rbegin(); j != cats.rend(); ++j)
        if (gemmi::starts_with(*tag, *j)) {
          tag = nullptr;
          break;
        }
    if (tag) {
      size_t dot = tag->find('.');
      if (dot != std::string::npos)
        cats.emplace_back(*tag, 0, dot + 1);
    }
  }
  return cats;
}

inline Item& Block::setup_loop_item(Table&& tab, const std::string& prefix,
                                    std::vector<std::string>&& tags) {
  Item *item;
  if (tab.loop_item) {
    item = tab.loop_item;
    item->loop.clear();
  } else if (tab.ok()) {
    item = &tab.bloc.items.at(tab.positions[0]);
    tab.erase();
    item->set_value(Item(LoopArg{}));
  } else {
    items.emplace_back(LoopArg{});
    item = &items.back();
  }
  for (std::string& tag : tags) {
    tag.insert(0, prefix);
    assert_tag(tag);
  }
  item->loop.tags = std::move(tags);
  return *item;
}

inline Loop& Block::setup_loop(Table&& tab, const std::string& prefix,
                               std::vector<std::string>&& tags) {
  return setup_loop_item(std::move(tab), prefix, std::move(tags)).loop;
}

inline Table Block::find(const std::string& prefix,
                         const std::vector<std::string>& tags) {
  Item* loop_item = nullptr;
  if (!tags.empty()) {
    if (tags[0][0] == '?')
      fail("The first tag in find() cannot be ?optional.");
    loop_item = find_loop(prefix + tags[0]).item();
  }

  std::vector<int> indices;
  indices.reserve(tags.size());
  if (loop_item) {
    for (const std::string& tag : tags) {
      std::string full_tag = prefix + (tag[0] != '?' ? tag : tag.substr(1));
      int idx = loop_item->loop.find_tag(full_tag);
      if (idx == -1 && tag[0] != '?') {
        loop_item = nullptr;
        indices.clear();
        break;
      }
      indices.push_back(idx);
    }
  } else {
    for (const std::string& tag : tags) {
      std::string full_tag = prefix + (tag[0] != '?' ? tag : tag.substr(1));
      if (const Item* p = find_pair_item(full_tag)) {
        indices.push_back(p - items.data());
      } else if (tag[0] == '?') {
        indices.push_back(-1);
      } else {
        indices.clear();
        break;
      }
    }
  }
  return Table{loop_item, *this, indices, prefix.length()};
}

inline Table Block::find_any(const std::string& prefix,
                             const std::vector<std::string>& tags) {
  std::vector<int> indices;
  for (auto tag = tags.begin(); tag != tags.end(); ++tag) {
    Column column = find_values(prefix + *tag);
    if (Item* item = column.item()) {
      if (item->type == ItemType::Loop) {
        indices.push_back(column.col());
        while (++tag != tags.end()) {
          int idx = item->loop.find_tag(prefix + *tag);
          if (idx != -1)
            indices.push_back(idx);
        }
        return Table{item, *this, indices, prefix.length()};
      }
      indices.push_back(item - items.data());
      while (++tag != tags.end())
        if (const Item* p = find_pair_item(prefix + *tag))
          indices.push_back(p - items.data());
      break;
    }
  }
  return Table{nullptr, *this, indices, prefix.length()};
}

inline Table Block::find_mmcif_category(std::string cat) {
  ensure_mmcif_category(cat);
  cat = gemmi::to_lower(cat);
  std::vector<int> indices;
  for (Item& i : items)
    if (i.has_prefix(cat)) {
      if (i.type == ItemType::Loop) {
        indices.resize(i.loop.tags.size());
        for (size_t j = 0; j != indices.size(); ++j) {
          indices[j] = j;
          const std::string& tag = i.loop.tags[j];
          if (!istarts_with(tag, cat))
            fail("Tag ", tag, " in loop with ", cat);
        }
        return Table{&i, *this, indices, cat.length()};
      }
      indices.push_back(&i - items.data());
    }
  return Table{nullptr, *this, indices, cat.length()};
}

inline bool Block::has_mmcif_category(std::string cat) const {
  ensure_mmcif_category(cat);
  cat = gemmi::to_lower(cat);
  for (const Item& i : items)
    if (i.has_prefix(cat))
      return true;
  return false;
}

/// @brief A parsed CIF file: a collection of blocks with optional metadata.
///
/// Represents the complete document structure after parsing a CIF file.
/// Contains one or more data blocks, each with tag-value pairs, loops, and frames.
struct Document {
  /// @brief Source filename or identifier (for error messages).
  std::string source;
  /// @brief All blocks in the document (data blocks).
  std::vector<Block> blocks;

  /// @brief Implementation detail: pointer to items of current block during parsing.
  /// (Used internally by the parser; not for public use.)
  std::vector<Item>* items_ = nullptr;

  /// @brief Add a new block to the document.
  /// @param name Block name (must be unique).
  /// @param pos Position to insert (-1 appends at end).
  /// @return Reference to the new Block.
  /// @throws std::runtime_error if name already exists.
  /// @throws std::out_of_range if pos is invalid.
  Block& add_new_block(const std::string& name, int pos=-1) {
    if (find_block(name))
      fail("Block with such name already exists: " + name);
    if (pos > 0 && static_cast<size_t>(pos) > blocks.size())
      throw std::out_of_range("add_new_block(): invalid position");
    return *blocks.emplace(pos < 0 ? blocks.end() : blocks.begin() + pos, name);
  }

  /// @brief Clear all blocks and source info.
  void clear() noexcept {
    source.clear();
    blocks.clear();
    items_ = nullptr;
  }

  /// @brief Get the single block from a one-block document (typical for mmCIF).
  /// @return Reference to blocks[0].
  /// @throws std::runtime_error if document has != 1 block.
  Block& sole_block() {
    if (blocks.size() > 1)
      fail("single data block expected, got " + std::to_string(blocks.size()));
    return blocks.at(0);
  }
  /// @brief Const overload of sole_block().
  const Block& sole_block() const {
    return const_cast<Document*>(this)->sole_block();
  }

  /// @brief Find a block by name (case-sensitive).
  /// @param name Block name.
  /// @return Pointer to the Block, or nullptr if not found.
  Block* find_block(const std::string& name) {
    for (Block& b : blocks)
      if (b.name == name)
        return &b;
    return nullptr;
  }
  /// @brief Const overload of find_block().
  const Block* find_block(const std::string& name) const {
    return const_cast<Document*>(this)->find_block(name);
  }
};


[[noreturn]]
inline void cif_fail(const std::string& source, const Block& b,
                     const Item& item, const std::string& s) {
  fail(cat(source, ':', item.line_number, " in data_", b.name, ": ", s));
}

inline void check_for_missing_values_in_block(const Block& block,
                                              const std::string& source) {
  for (const Item& item : block.items) {
    if (item.type == ItemType::Pair) {
      if (item.pair[1].empty())
        cif_fail(source, block, item, item.pair[0] + " has no value");
    } else if (item.type == ItemType::Frame) {
      check_for_missing_values_in_block(item.frame, source);
    }
  }
}

// Throw an error if any item (pair) value is missing
inline void check_for_missing_values(const Document& d) {
  for (const Block& block : d.blocks)
    check_for_missing_values_in_block(block, d.source);
}

// Throw an error if any block name, frame name or tag is duplicated.
inline void check_for_duplicates(const Document& d) {
  // check for duplicate block names (except empty "" which is global_)
  std::unordered_set<std::string> names;
  for (const Block& block : d.blocks) {
    bool ok = names.insert(gemmi::to_lower(block.name)).second;
    if (!ok && !block.name.empty())
      fail(d.source + ": duplicate block name: ", block.name);
  }
  // check for dups inside each block
  std::unordered_set<std::string> frame_names;
  for (const Block& block : d.blocks) {
    names.clear();
    frame_names.clear();
    for (const Item& item : block.items) {
      if (item.type == ItemType::Pair) {
        bool ok = names.insert(gemmi::to_lower(item.pair[0])).second;
        if (!ok)
          cif_fail(d.source, block, item, "duplicate tag " + item.pair[0]);
      } else if (item.type == ItemType::Loop) {
        for (const std::string& t : item.loop.tags) {
          bool ok = names.insert(gemmi::to_lower(t)).second;
          if (!ok)
            cif_fail(d.source, block, item, "duplicate tag " + t);
        }
      } else if (item.type == ItemType::Frame) {
        bool ok = frame_names.insert(gemmi::to_lower(item.frame.name)).second;
        if (!ok)
          cif_fail(d.source, block, item, "duplicate save_" + item.frame.name);
      }
    }
  }
}

// Empty loop is not a valid CIF syntax, but we parse it to accommodate
// some broken CIF files. Only check_level>=2 shows an error.
inline void check_empty_loops(const cif::Block& block, const std::string& source) {
  for (const cif::Item& item : block.items) {
    if (item.type == cif::ItemType::Loop) {
      if (item.loop.values.empty() && !item.loop.tags.empty())
        cif_fail(source, block, item, "empty loop with " + item.loop.tags[0]);
    } else if (item.type == cif::ItemType::Frame) {
      check_empty_loops(item.frame, source);
    }
  }
}

inline bool is_text_field(const std::string& val) {
  size_t len = val.size();
  return len > 2 && val[0] == ';' && (val[len-2] == '\n' || val[len-2] == '\r');
}

inline std::string quote(std::string v) {
  if (v.empty())
    return "''";
  if (std::all_of(v.begin(), v.end(), [](char c) { return char_table(c) == 1; })
      && !is_null(v))
    return v;
  char q = ';';
  if (std::memchr(v.c_str(), '\n', v.size()) == nullptr) {
    if (std::memchr(v.c_str(), '\'', v.size()) == nullptr)
      q = '\'';
    else if (std::memchr(v.c_str(), '"', v.size()) == nullptr)
      q = '"';
  }
  v.insert(v.begin(), q);
  if (q == ';')
    v += '\n';
  v += q;
  return v;
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace cif
} // namespace gemmi
#endif
