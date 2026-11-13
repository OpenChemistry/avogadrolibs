// Copyright 2017 Global Phasing Ltd.
//
// interface to stb_sprintf: snprintf_z, to_str(float|double)

#ifndef GEMMI_SPRINTF_HPP_
#define GEMMI_SPRINTF_HPP_

#include <string>
#ifdef __has_include
# if __has_include(<charconv>) && !(defined(_MSVC_LANG) && _MSVC_LANG < 201703L)
#  include <charconv>
# endif
#endif

#if __cpp_lib_to_chars < 201611L
# include <algorithm> // for min
#endif

#include "fail.hpp"  // for GEMMI_DLL

namespace gemmi {

// On MinGW format(printf) doesn't support %zu.
#if (defined(__GNUC__) && !defined(__MINGW32__)) || defined(__clang__)
# define GEMMI_ATTRIBUTE_FORMAT(fmt,va) __attribute__((format(printf,fmt,va)))
#else
# define GEMMI_ATTRIBUTE_FORMAT(fmt,va)
#endif
/// @brief snprintf-style string formatting (locale-independent, always zero-terminated)
/// @details Uses stb_snprintf which ignores locale and guarantees zero-termination
///          (hence the _z suffix). Signature follows snprintf.
/// @param buf output character buffer
/// @param count maximum number of characters to write (including terminator)
/// @param fmt printf-style format string
/// @return number of characters written (not including the terminator), or negative on error
GEMMI_DLL int snprintf_z(char *buf, int count, char const *fmt, ...)
                                                         GEMMI_ATTRIBUTE_FORMAT(3,4);

/// @brief sprintf-style string formatting (locale-independent, always zero-terminated)
/// @details Uses stb_sprintf which ignores locale and guarantees zero-termination.
///          The buffer must be large enough for the formatted output.
/// @param buf output character buffer (must be large enough)
/// @param fmt printf-style format string
/// @return number of characters written (not including the terminator), or negative on error
GEMMI_DLL int sprintf_z(char *buf, char const *fmt, ...) GEMMI_ATTRIBUTE_FORMAT(2,3);

/// @brief Convert a double to a string with default precision
/// @param d the double value to convert
/// @return string representation using format "%.9g"
inline std::string to_str(double d) {
  char buf[24];
  int len = sprintf_z(buf, "%.9g", d);
  return std::string(buf, len > 0 ? len : 0);
}

/// @brief Convert a float to a string with default precision
/// @param d the float value to convert
/// @return string representation using format "%.6g"
inline std::string to_str(float d) {
  char buf[16];
  int len = sprintf_z(buf, "%.6g", d);
  return std::string(buf, len > 0 ? len : 0);
}

/// @brief Convert a double to a string with specified decimal precision
/// @tparam Prec decimal precision (0-6 places after decimal point)
/// @param d the double value to convert
/// @return string representation with fixed decimal places or scientific notation
/// @details Uses fixed-point format for values in [-1e8, 1e8), scientific notation otherwise
template<int Prec>
std::string to_str_prec(double d) {
  static_assert(Prec >= 0 && Prec < 7, "unsupported precision");
  char buf[16];
  int len = d > -1e8 && d < 1e8 ? sprintf_z(buf, "%.*f", Prec, d)
                                : sprintf_z(buf, "%g", d);
  return std::string(buf, len > 0 ? len : 0);
}

/// @brief Convert an integer to a zero-terminated C-string
/// @details Uses std::to_chars if available (C++17), otherwise snprintf_z.
///          Guarantees zero-termination within the output range.
/// @param first pointer to start of output buffer
/// @param last pointer to one-past-end of output buffer
/// @param value the integer value to convert
/// @return pointer to the zero terminator in the output buffer
inline char* to_chars_z(char* first, char* last, int value) {
#if __cpp_lib_to_chars >= 201611L
  auto result = std::to_chars(first, last-1, value);
  *result.ptr = '\0';
  return result.ptr;
#else
  int n = snprintf_z(first, int(last - first), "%d", value);
  return std::min(first + n, last - 1);
#endif
}

/// @brief Convert a size_t to a zero-terminated C-string
/// @details Uses std::to_chars if available (C++17), otherwise snprintf_z.
///          Guarantees zero-termination within the output range.
/// @param first pointer to start of output buffer
/// @param last pointer to one-past-end of output buffer
/// @param value the size_t value to convert
/// @return pointer to the zero terminator in the output buffer
inline char* to_chars_z(char* first, char* last, size_t value) {
#if __cpp_lib_to_chars >= 201611L
  auto result = std::to_chars(first, last-1, value);
  *result.ptr = '\0';
  return result.ptr;
#else
  int n = snprintf_z(first, int(last - first), "%zu", value);
  return std::min(first + n, last - 1);
#endif
}

} // namespace gemmi
#endif
