// Copyright 2017 Global Phasing Ltd.

/// @file
/// @brief Parsing CIF numeric values (numb) with optional standard uncertainty.

#ifndef GEMMI_NUMB_HPP_
#define GEMMI_NUMB_HPP_

#include <cmath>   // for NAN
#include <string>
#include "third_party/fast_float.h"

namespace gemmi {
namespace cif {

/// Parse a CIF numeric value (numb), optionally including standard uncertainty.
///
/// In CIF format, numeric values (numb) can include optional standard uncertainty
/// (s.u.) in parentheses, e.g., "1.23(8)" represents 1.23 with s.u. of 0.08.
/// The s.u. information is parsed and skipped; only the numeric value is returned.
///
/// Note: mmCIF files typically do not use s.u. notation for numeric values;
/// they define their own numeric data categories instead.
///
/// @param s   String containing the numeric value to parse
/// @param nan Default return value if parsing fails (default: NaN)
/// @return Parsed numeric value (with s.u. removed), or nan if invalid
///
/// @note The function accepts leading '+' signs and rejects NaN, Inf, and -Inf
///       as they are not allowed in standard CIF format.
///
/// @example
/// @code
/// double d = as_number("1.234");        // returns 1.234
/// double d = as_number("1.234(5)");     // returns 1.234 (s.u. ignored)
/// double d = as_number("invalid");      // returns NAN
/// @endcode
inline double as_number(const std::string& s, double nan=NAN) {
  const char* start = s.data();
  const char* end = s.data() + s.size();
  if (*start == '+')
    ++start;
  // NaN, Inf and -Inf are not allowed in CIF
  char f = start[int(*start == '-')] | 0x20;
  if (f == 'i' || f == 'n')
    return nan;

  double d;
  auto result = fast_float::from_chars(start, end, d);
  if (result.ec != std::errc())
    return nan;
  if (*result.ptr == '(') {
    const char* p = result.ptr + 1;
    while (*p >= '0' && *p <= '9')
      ++p;
    if (*p == ')')
      result.ptr = p + 1;
  }
  return result.ptr == end ? d : nan;
}

/// Check if a string represents a valid CIF numeric value (numb).
///
/// @param s String to check
/// @return true if the string is a valid CIF number, false otherwise
inline bool is_numb(const std::string& s) {
  return !std::isnan(as_number(s));
}


// Template overloads for use in generic type conversion functions
// (see also as_any() functions in cifdoc.hpp)

/// Parse CIF numeric value as a float (template specialization).
///
/// @param s    String containing the numeric value
/// @param null Fallback value if parsing fails
/// @return Parsed float value, or null on failure
inline float as_any(const std::string& s, float null) {
  return (float) as_number(s, null);
}

/// Parse CIF numeric value as a double (template specialization).
///
/// @param s    String containing the numeric value
/// @param null Fallback value if parsing fails
/// @return Parsed double value, or null on failure
inline double as_any(const std::string& s, double null) {
  return as_number(s, null);
}

} // namespace cif
} // namespace gemmi
#endif
