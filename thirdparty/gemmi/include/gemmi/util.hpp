// Copyright 2017 Global Phasing Ltd.
//
// Utilities. Mostly for working with strings and vectors.

#ifndef GEMMI_UTIL_HPP_
#define GEMMI_UTIL_HPP_

#include <cassert>
#include <cctype>     // for isspace
#include <cstring>    // for strncmp
#include <algorithm>  // for equal, find, remove_if
#include <iterator>   // for begin, end, make_move_iterator
#include <string>
#include <vector>

namespace gemmi {

//   #####   string helpers   #####

/// @brief Append an integer to a string.
/// @param out Output string
/// @param v Integer value to append
inline void append_to_str(std::string& out, int v) { out += std::to_string(v); }

/// @brief Append an unsigned integer to a string.
/// @param out Output string
/// @param v Size/unsigned value to append
inline void append_to_str(std::string& out, size_t v) { out += std::to_string(v); }

/// @brief Double appending is not supported.
void append_to_str(std::string& out, double) = delete;

/// @brief Append any other type to a string (calls operator+).
/// @tparam T Type to append
/// @param out Output string
/// @param v Value to append
template<typename T>
void append_to_str(std::string& out, const T& v) { out += v; }

/// @brief Concatenate values into a string (base case).
/// @param out Output string
inline void cat_to(std::string&) {}

/// @brief Recursively concatenate values into a string.
/// @tparam T First value type
/// @tparam Args Remaining value types
/// @param out Output string
/// @param value First value to append
/// @param args Remaining values to append recursively
template <typename T, typename... Args>
void cat_to(std::string& out, const T& value, Args const&... args) {
  append_to_str(out, value);
  cat_to(out, args...);
}

/// @brief Concatenate variadic arguments into a new string.
/// @tparam Args Value types
/// @param args Values to concatenate
/// @return Concatenated string
template <class... Args>
std::string cat(Args const&... args) {
  std::string out;
  cat_to(out, args...);
  return out;
}

/// @brief Check if a string starts with a given prefix.
/// @param str String to check
/// @param prefix Prefix to look for
/// @return True if str begins with prefix
inline bool starts_with(const std::string& str, const std::string& prefix) {
  size_t sl = prefix.length();
  return str.length() >= sl && str.compare(0, sl, prefix) == 0;
}

/// @brief Check if a string starts with a string literal prefix.
/// @tparam N Length of string literal
/// @param a String to check (C string)
/// @param b String literal prefix
/// @return True if a starts with b
template<size_t N> bool starts_with(const char* a, const char (&b)[N]) {
  return std::strncmp(a, b, N-1) == 0;
}

/// @brief Check if a string ends with a given suffix.
/// @param str String to check
/// @param suffix Suffix to look for
/// @return True if str ends with suffix
inline bool ends_with(const std::string& str, const std::string& suffix) {
  size_t sl = suffix.length();
  return str.length() >= sl && str.compare(str.length() - sl, sl, suffix) == 0;
}

/// @brief Convert a single character to lowercase (faster than std::tolower).
/// @param c Character to convert
/// @return Lowercase version of c, or c if not uppercase
inline char lower(char c) {
  if (c >= 'A' && c <= 'Z')
    return c | 0x20;
  return c;
}

/// @brief Convert a single character to uppercase (ASCII letters only).
/// @param c Character to convert
/// @return Uppercase version of c (works only for a-zA-Z)
inline char alpha_up(char c) { return c & ~0x20; }

/// @brief Convert a string to lowercase.
/// @param str String to convert
/// @return Lowercase copy of str
inline std::string to_lower(std::string str) {
  for (char& c : str)
    if (c >= 'A' && c <= 'Z')
      c |= 0x20;
  return str;
}

/// @brief Convert a string to uppercase.
/// @param str String to convert
/// @return Uppercase copy of str
inline std::string to_upper(std::string str) {
  for (char& c : str)
    if (c >= 'a' && c <= 'z')
      c &= ~0x20;
  return str;
}

/// @brief Case-insensitive single character comparison.
/// @param a First character
/// @param b Second character
/// @return True if characters are equal (ignoring case)
inline bool isame(char a, char b) {
  return a == b || ((a^b) == 0x20 && (a|0x20) >= 'a' && (a|0x20) <= 'z');
}

/// @brief Case-insensitive string equality starting at an offset.
/// @details The second argument must be lowercase for comparison.
/// @param str String to check
/// @param offset Starting offset in str
/// @param low Lowercase reference string
/// @return True if (str[offset:] == low) case-insensitively
inline bool iequal_from(const std::string& str, size_t offset, const std::string& low) {
  return str.length() == low.length() + offset &&
         std::equal(std::begin(low), std::end(low), str.begin() + offset,
                    [](char c1, char c2) { return c1 == lower(c2); });
}

/// @brief Case-insensitive string equality.
/// @details The second argument must be lowercase for comparison.
/// @param str String to check
/// @param low Lowercase reference string
/// @return True if str == low (case-insensitively)
inline bool iequal(const std::string& str, const std::string& low) {
  return iequal_from(str, 0, low);
}

/// @brief Case-insensitive prefix check.
/// @param str String to check
/// @param prefix Lowercase prefix to look for
/// @return True if str starts with prefix (case-insensitively)
inline bool istarts_with(const std::string& str, const std::string& prefix) {
  return str.length() >= prefix.length() &&
         std::equal(std::begin(prefix), std::end(prefix), str.begin(),
                    [](char c1, char c2) { return c1 == lower(c2); });
}

/// @brief Case-insensitive suffix check.
/// @param str String to check
/// @param suffix Lowercase suffix to look for
/// @return True if str ends with suffix (case-insensitively)
inline bool iends_with(const std::string& str, const std::string& suffix) {
  size_t sl = suffix.length();
  return str.length() >= sl &&
         std::equal(std::begin(suffix), std::end(suffix), str.end() - sl,
                    [](char c1, char c2) { return c1 == lower(c2); });
}

/// @brief Check if string ends with suffix or suffix.gz (case-insensitive).
/// @param str String to check
/// @param suffix Lowercase suffix to look for (or suffix.gz)
/// @return True if str ends with suffix or suffix.gz
inline bool giends_with(const std::string& str, const std::string& suffix) {
  return iends_with(str, suffix) || iends_with(str, suffix + ".gz");
}

/// @brief Trim whitespace from both ends of a string.
/// @param str String to trim
/// @return Trimmed copy of str
inline std::string trim_str(const std::string& str) {
  const std::string ws = " \r\n\t";
  std::string::size_type first = str.find_first_not_of(ws);
  if (first == std::string::npos)
    return std::string{};
  std::string::size_type last = str.find_last_not_of(ws);
  return str.substr(first, last - first + 1);
}

/// @brief Trim whitespace from the right end of a string.
/// @param str String to trim
/// @return Right-trimmed copy of str
inline std::string rtrim_str(const std::string& str) {
  std::string::size_type last = str.find_last_not_of(" \r\n\t");
  return str.substr(0, last == std::string::npos ? 0 : last + 1);
}

/// @brief Trim whitespace from the right end of a C string.
/// @param start Pointer to start of string
/// @param end Pointer to end of string (after last character, typically \\0); nullptr to auto-detect
/// @return Pointer to first non-whitespace character from the right
inline const char* rtrim_cstr(const char* start, const char* end=nullptr) {
  if (!start)
    return nullptr;
  if (!end) {
    end = start;
    while (*end != '\0')
      ++end;
  }
  while (end > start && std::isspace(end[-1]))
    --end;
  return end;
}

namespace impl {
inline size_t length(char) { return 1; }
inline size_t length(const std::string& s) { return s.length(); }
}

/// @brief Split a string by a separator into a vector (append to existing vector).
/// @details Takes a single separator (char or string); may return empty fields.
/// @tparam S Separator type (char or string)
/// @param str String to split
/// @param sep Separator to split on
/// @param result Vector to append results to
template<typename S>
void split_str_into(const std::string& str, S sep,
                    std::vector<std::string>& result) {
  std::size_t start = 0, end;
  while ((end = str.find(sep, start)) != std::string::npos) {
    result.emplace_back(str, start, end - start);
    start = end + impl::length(sep);
  }
  result.emplace_back(str, start);
}

/// @brief Split a string by a separator into a vector.
/// @details Takes a single separator (char or string); may return empty fields.
/// @tparam S Separator type (char or string)
/// @param str String to split
/// @param sep Separator to split on
/// @return Vector of substrings
template<typename S>
std::vector<std::string> split_str(const std::string& str, S sep) {
  std::vector<std::string> result;
  split_str_into(str, sep, result);
  return result;
}

/// @brief Split a string by multiple single-character separators (append to existing vector).
/// @details Discards empty fields (unlike split_str_into).
/// @param str String to split
/// @param seps String of separator characters
/// @param result Vector to append results to
inline void split_str_into_multi(const std::string& str, const char* seps,
                                 std::vector<std::string>& result) {
  std::size_t start = str.find_first_not_of(seps);
  while (start != std::string::npos) {
    std::size_t end = str.find_first_of(seps, start);
    result.emplace_back(str, start, end - start);
    start = str.find_first_not_of(seps, end);
  }
}

/// @brief Split a string by multiple single-character separators into a vector.
/// @details Discards empty fields (unlike split_str).
/// @param str String to split
/// @param seps String of separator characters (default: space and tab)
/// @return Vector of non-empty substrings
inline std::vector<std::string> split_str_multi(const std::string& str,
                                                const char* seps=" \t") {
  std::vector<std::string> result;
  split_str_into_multi(str, seps, result);
  return result;
}

/// @brief Join elements from iterators with a separator.
/// @tparam T Iterator type
/// @tparam S Separator type
/// @tparam F Getter function type
/// @param begin Iterator to first element
/// @param end Iterator to end (exclusive)
/// @param sep Separator to insert between elements
/// @param getter Function to convert each element to string
/// @return Joined string
template<typename T, typename S, typename F>
std::string join_str(T begin, T end, const S& sep, const F& getter) {
  std::string r;
  bool first = true;
  for (T i = begin; i != end; ++i) {
    if (!first)
      r += sep;
    r += getter(*i);
    first = false;
  }
  return r;
}

/// @brief Join elements from iterators with a separator.
/// @tparam T Iterator type
/// @tparam S Separator type
/// @param begin Iterator to first element
/// @param end Iterator to end (exclusive)
/// @param sep Separator to insert between elements
/// @return Joined string
template<typename T, typename S>
std::string join_str(T begin, T end, const S& sep) {
  return join_str(begin, end, sep, [](const std::string& t) { return t; });
}

/// @brief Join elements from an iterable with a separator.
/// @tparam T Iterable type
/// @tparam S Separator type
/// @tparam F Getter function type
/// @param iterable Container of elements
/// @param sep Separator to insert between elements
/// @param getter Function to convert each element to string
/// @return Joined string
template<typename T, typename S, typename F>
std::string join_str(const T& iterable, const S& sep, const F& getter) {
  return join_str(iterable.begin(), iterable.end(), sep, getter);
}

/// @brief Join elements from an iterable with a separator.
/// @tparam T Iterable type
/// @tparam S Separator type
/// @param iterable Container of string elements
/// @param sep Separator to insert between elements
/// @return Joined string
template<typename T, typename S>
std::string join_str(const T& iterable, const S& sep) {
  return join_str(iterable.begin(), iterable.end(), sep);
}

/// @brief Append an item to a string with a separator if string is non-empty.
/// @tparam T Item type
/// @tparam S Separator type
/// @param str String to append to
/// @param sep Separator to insert before item
/// @param item Item to append
template<typename T, typename S>
void string_append_sep(std::string& str, S sep, const T& item) {
  if (!str.empty())
    str += sep;
  str += item;
}

/// @brief Replace all occurrences of a substring with another.
/// @param s String to modify in-place
/// @param old Substring to find
/// @param new_ Replacement substring
inline void replace_all(std::string &s,
                        const std::string &old, const std::string &new_) {
  std::string::size_type pos = 0;
  while ((pos = s.find(old, pos)) != std::string::npos) {
    s.replace(pos, old.size(), new_);
    pos += new_.size();
  }
}

/// @brief Check if a name appears as an item in a separated list.
/// @param name Item to search for
/// @param list Separated list of items
/// @param sep Separator character (default: comma)
/// @return True if name appears as a complete item in list
inline bool is_in_list(const std::string& name, const std::string& list,
                       char sep=',') {
  if (name.length() >= list.length())
    return name == list;
  for (size_t start=0, end=0; end != std::string::npos; start=end+1) {
    end = list.find(sep, start);
    if (list.compare(start, end - start, name) == 0)
      return true;
  }
  return false;
}

//   #####   vector helpers   #####

/// @brief Check if a value exists in a vector.
/// @tparam T Vector element type
/// @param x Value to search for
/// @param v Vector to search in
/// @return True if x is found in v
template <class T>
bool in_vector(const T& x, const std::vector<T>& v) {
  return std::find(v.begin(), v.end(), x) != v.end();
}

/// @brief Check if any element in a vector matches a predicate.
/// @tparam F Predicate function type
/// @tparam T Vector element type
/// @param f Predicate function
/// @param v Vector to search in
/// @return True if predicate matches any element
template <typename F, typename T>
bool in_vector_f(F f, const std::vector<T>& v) {
  return std::find_if(v.begin(), v.end(), f) != v.end();
}

/// @brief Get pointer to one-past-end of a vector (like end()).
/// @tparam T Vector element type
/// @param v Vector
/// @return Pointer to one-past-end (v.data() + v.size())
template <class T>
T* vector_end_ptr(std::vector<T>& v) { return v.data() + v.size(); }

/// @brief Get const pointer to one-past-end of a vector.
/// @tparam T Vector element type
/// @param v Vector
/// @return Const pointer to one-past-end
template <class T>
const T* vector_end_ptr(const std::vector<T>& v) { return v.data() + v.size(); }

/// @brief Move elements from source vector to destination vector.
/// @tparam T Vector element type
/// @param dst Destination vector
/// @param src Source vector (moved from, will be empty)
template <class T>
void vector_move_extend(std::vector<T>& dst, std::vector<T>&& src) {
  if (dst.empty())
    dst = std::move(src);
  else
    dst.insert(dst.end(), std::make_move_iterator(src.begin()),
                          std::make_move_iterator(src.end()));
}

/// @brief Remove all elements matching a condition from a vector.
/// @tparam T Vector element type
/// @tparam F Predicate function type
/// @param v Vector to modify in-place
/// @param condition Predicate; elements matching return true are removed
template <class T, typename F>
void vector_remove_if(std::vector<T>& v, F&& condition) {
  v.erase(std::remove_if(v.begin(), v.end(), condition), v.end());
}

/// @brief Insert columns into a 2D array stored as a flat vector.
/// @tparam T Array element type
/// @param data 2D array (old_width x length) stored in a flat vector
/// @param old_width Original number of columns
/// @param length Number of rows
/// @param n Number of new columns to insert
/// @param pos Column position to insert at
/// @param new_value Value to fill new columns with
template <class T>
void vector_insert_columns(std::vector<T>& data, size_t old_width,
                           size_t length, size_t n, size_t pos, const T& new_value) {
  assert(data.size() == old_width * length);
  assert(pos <= old_width);
  data.resize(data.size() + n * length);
  typename std::vector<T>::iterator dst = data.end();
  for (size_t i = length; i-- != 0; ) {
    for (size_t j = old_width; j-- != pos; )
      *--dst = data[i * old_width + j];
    for (size_t j = n; j-- != 0; )
      *--dst = new_value;
    for (size_t j = pos; j-- != 0; )
      *--dst = data[i * old_width + j];
  }
  assert(dst == data.begin());
}

/// @brief Remove a column from a 2D array stored as a flat vector.
/// @tparam T Array element type
/// @param data 2D array with (new_width + 1) columns stored in a flat vector
/// @param new_width Number of columns after removal
/// @param pos Column position to remove
template <class T>
void vector_remove_column(std::vector<T>& data, size_t new_width, size_t pos) {
  assert(pos <= new_width);
  for (size_t source = pos + 1; source < data.size(); ++source)
    for (size_t i = 0; i < new_width && source < data.size(); ++i)
      data[pos++] = data[source++];
  data.resize(pos);
}


//   #####   other helpers   #####

/// @brief Generate a case-insensitive numeric ID for 4-letter strings.
/// @param s Pointer to 4 characters (or 3 chars + NUL); space and NUL are equivalent
/// @return Numeric ID suitable for case-insensitive comparison
constexpr int ialpha4_id(const char* s) {
  return (s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3]) & ~0x20202020;
}

/// @brief Generate a case-insensitive numeric ID for 3-letter strings.
/// @param s Pointer to 3 characters
/// @return Numeric ID suitable for case-insensitive comparison
constexpr int ialpha3_id(const char* s) {
  return (s[0] << 16 | s[1] << 8 | s[2]) & ~0x20202020;
}

} // namespace gemmi
#endif
