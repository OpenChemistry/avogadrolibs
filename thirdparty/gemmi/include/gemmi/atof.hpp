// Copyright 2020 Global Phasing Ltd.
//
// Functions that convert strings to floating-point numbers ignoring locale.
// Simple wrappers around fastfloat::from_chars().

#ifndef GEMMI_ATOF_HPP_
#define GEMMI_ATOF_HPP_

#include "atox.hpp"   // for is_space
#include "third_party/fast_float.h"

namespace gemmi {

/// @brief Result type from fast_float::from_chars.
using fast_float::from_chars_result;

/// @brief Fast locale-independent string to double conversion with range.
/// @param start pointer to string start
/// @param end pointer to one-past-end
/// @param d reference to output double
/// @return from_chars_result with ptr field pointing to first non-converted character
/// @details Skips leading whitespace and optional '+' sign before parsing.
inline from_chars_result fast_from_chars(const char* start, const char* end, double& d) {
  while (start < end && is_space(*start))
    ++start;
  if (start < end && *start == '+')
    ++start;
  return fast_float::from_chars(start, end, d);
}

/// @brief Fast locale-independent string to double conversion (null-terminated).
/// @param start pointer to null-terminated string
/// @param d reference to output double
/// @return from_chars_result with ptr field pointing to first non-converted character
/// @details Skips leading whitespace and optional '+' sign before parsing.
inline from_chars_result fast_from_chars(const char* start, double& d) {
  while (is_space(*start))
    ++start;
  if (*start == '+')
    ++start;
  return fast_float::from_chars(start, start + std::strlen(start), d);
}

/// @brief Fast locale-independent string to double conversion with optional end pointer.
/// @param p pointer to string (null-terminated)
/// @param endptr optional pointer to receive end of parsed string (may be nullptr)
/// @return the parsed double value
inline double fast_atof(const char* p, const char** endptr=nullptr) {
  double d = 0;
  auto result = fast_from_chars(p, d);
  if (endptr)
    *endptr = result.ptr;
  return d;
}

} // namespace gemmi
#endif
