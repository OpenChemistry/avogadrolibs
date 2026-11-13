// Copyright 2018 Global Phasing Ltd.
//
// Locale-independent functions that convert strings to integers,
// equivalents of standard isspace and isdigit, and a few helper functions.
//
// This file is named similarly to the standard functions atoi() and atof().
// But the functions here are not meant to be equivalent to the standard
// library functions. They are locale-independent (a good thing when reading
// numbers from files). They don't set errno, don't signal overflow and
// underflow. Due to the limited scope these functions tend to be faster
// than the standard-library ones.

#ifndef GEMMI_ATOX_HPP_
#define GEMMI_ATOX_HPP_

#include <cstdint>
#include <stdexcept>  // for invalid_argument
#include <string>

namespace gemmi {

/// @brief Locale-independent isspace equivalent (C locale only, no EOF handling).
/// @param c character to test
/// @return true if c is whitespace (tab, newline, vertical tab, form feed, carriage return, or space)
inline bool is_space(char c) {
  static const std::uint8_t table[256] = { // 1 for 9-13 and 32
    0,0,0,0,0,0,0,0, 0,1,1,1,1,1,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0
  };
  return table[(std::uint8_t)c] != 0;
}

/// @brief Locale-independent isblank equivalent (C locale only, no EOF handling).
/// @param c character to test
/// @return true if c is space or tab
inline bool is_blank(char c) {
  return c == ' ' || c == '\t';
}

/// @brief Locale-independent isdigit equivalent (C locale only, no EOF handling).
/// @param c character to test
/// @return true if c is a decimal digit (0-9)
inline bool is_digit(char c) {
  return c >= '0' && c <= '9';
}

/// @brief Skip leading blank characters (spaces and tabs).
/// @param p pointer to string (may be null)
/// @return pointer to first non-blank character, or end of string
inline const char* skip_blank(const char* p) {
  if (p)
    while (is_blank(*p))
      ++p;
  return p;
}

/// @brief Skip word (non-whitespace characters).
/// @param p pointer to string (may be null)
/// @return pointer to first whitespace or null terminator
inline const char* skip_word(const char* p) {
  if (p)
    while (*p != '\0' && !is_space(*p))
      ++p;
  return p;
}

/// @brief Read a word from the start of a line (skipping leading blanks).
/// @param line pointer to start of line
/// @return string containing the word
inline std::string read_word(const char* line) {
  line = skip_blank(line);
  return std::string(line, skip_word(line));
}

/// @brief Read a word from the start of a line with end pointer.
/// @param line pointer to start of line
/// @param endptr pointer to receive pointer to character after word
/// @return string containing the word
inline std::string read_word(const char* line, const char** endptr) {
  line = skip_blank(line);
  *endptr = skip_word(line);
  return std::string(line, *endptr);
}

/// @brief Convert string to signed integer (locale-independent, no overflow checking).
/// @param p pointer to string
/// @param checked if true, throw std::invalid_argument if string is not a valid integer
/// @param length max length to parse (0 = unlimited)
/// @return the converted integer
/// @throws std::invalid_argument if checked=true and string is invalid
inline int string_to_int(const char* p, bool checked, size_t length=0) {
  int mult = -1;
  int n = 0;
  size_t i = 0;
  while ((length == 0 || i < length) && is_space(p[i]))
    ++i;
  if (p[i] == '-') {
    mult = 1;
    ++i;
  } else if (p[i] == '+') {
    ++i;
  }
  bool has_digits = false;
  // use negative numbers because INT_MIN < -INT_MAX
  for (; (length == 0 || i < length) && is_digit(p[i]); ++i) {
    n = n * 10 - (p[i] - '0');
    has_digits = true;
  }
  if (checked) {
    while ((length == 0 || i < length) && is_space(p[i]))
      ++i;
    if (!has_digits || p[i] != '\0')
      throw std::invalid_argument("not an integer: " +
                                  std::string(p, length ? length : i+1));
  }
  return mult * n;
}

/// @brief Convert std::string to signed integer (checked version).
/// @param str the string to convert
/// @param checked if true, throw std::invalid_argument if string is not a valid integer
/// @return the converted integer
/// @throws std::invalid_argument if checked=true and string is invalid
inline int string_to_int(const std::string& str, bool checked) {
  return string_to_int(str.c_str(), checked);
}

/// @brief Fast atoi-like conversion with optional end pointer (unchecked, allows partial parse).
/// @param p pointer to null-terminated string
/// @param endptr optional pointer to receive pointer to first non-digit character
/// @return the converted integer
inline int simple_atoi(const char* p, const char** endptr=nullptr) {
  int mult = -1;
  int n = 0;
  while (is_space(*p))
    ++p;
  if (*p == '-') {
    mult = 1;
    ++p;
  } else if (*p == '+') {
    ++p;
  }
  for (; is_digit(*p); ++p)
    n = n * 10 - (*p - '0'); // use negative numbers because INT_MIN < -INT_MAX
  if (endptr)
    *endptr = p;
  return mult * n;
}

/// @brief Fast atoi-like conversion without sign (positive only, unchecked).
/// @param p pointer to null-terminated string
/// @param endptr optional pointer to receive pointer to first non-digit character
/// @return the converted non-negative integer
inline int no_sign_atoi(const char* p, const char** endptr=nullptr) {
  int n = 0;
  while (is_space(*p))
    ++p;
  for (; is_digit(*p); ++p)
    n = n * 10 + (*p - '0');
  if (endptr)
    *endptr = p;
  return n;
}

} // namespace gemmi
#endif
