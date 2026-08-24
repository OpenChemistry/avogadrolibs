/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_UTILITIES_H
#define AVOGADRO_CORE_UTILITIES_H

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <istream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace Avogadro::Core {

/**
 * @brief Read one line from @p in, clearing @p line if the read fails.
 * @param in The stream to read from.
 * @param line Receives the line read, or an empty string on failure.
 * @return True if a line was read, false at end of file or on error.
 *
 * std::getline only clears its target string after the sentry check succeeds,
 * so on a stream that has already failed it leaves the previous line in place.
 * File parsers that loop until they see a blank line therefore never terminate
 * at end of file, and keep re-parsing the last line read. Use this in place of
 * std::getline in those loops.
 */
inline bool getLine(std::istream& in, std::string& line)
{
  if (!std::getline(in, line)) {
    line.clear();
    return false;
  }
  return true;
}

/**
 * @brief Split the supplied @p string by the @p delimiter.
 * @param string The string to be split up.
 * @param delimiter The delimiter to split the string by.
 * @param skipEmpty If true any empty items will be skipped.
 * @return A vector containing the items.
 */
inline std::vector<std::string> split(const std::string& string, char delimiter,
                                      bool skipEmpty = true)
{
  std::vector<std::string> elements;
  std::stringstream stringStream(string);
  std::string item;
  while (std::getline(stringStream, item, delimiter)) {
    if (skipEmpty && item.empty())
      continue;
    elements.push_back(item);
  }
  return elements;
}

/**
 * @brief Search the input string for the search string.
 * @param input String to be examined.
 * @param search String that will be searched for.
 * @return True if the string contains search, false otherwise.
 */
inline bool contains(const std::string& input, const std::string& search,
                     bool caseSensitive = true)
{
  if (caseSensitive) {
    return input.find(search) != std::string::npos;
  } else {
    std::string inputLower = input;
    std::string searchLower = search;
    std::transform(inputLower.begin(), inputLower.end(), inputLower.begin(),
                   ::tolower);
    std::transform(searchLower.begin(), searchLower.end(), searchLower.begin(),
                   ::tolower);
    return inputLower.find(searchLower) != std::string::npos;
  }
}

/**
 * @brief Efficient method to confirm input starts with the search string.
 * @param input String to be examined.
 * @param search String that will be searched for.
 * @return True if the string starts with search, false otherwise.
 */
inline bool startsWith(const std::string& input, const std::string& search)
{
  return input.size() >= search.size() &&
         input.compare(0, search.size(), search) == 0;
}

/**
 * @brief Efficient method to confirm input ends with the ending string.
 * @param input String to be examined.
 * @param ending String that will be searched for.
 * @return True if the string ends with ending, false otherwise.
 */
inline bool endsWith(std::string const& input, std::string const& ending)
{
  if (ending.size() > input.size())
    return false;
  return std::equal(ending.rbegin(), ending.rend(), input.rbegin());
}

/**
 * @brief Trim a string of whitespace from the left and right.
 */
inline std::string trimmed(const std::string& input)
{
  size_t start = input.find_first_not_of(" \n\r\t");
  size_t end = input.find_last_not_of(" \n\r\t");
  if (start == std::string::npos && end == std::string::npos)
    return "";
  return input.substr(start, end - start + 1);
}

/**
 * @brief Remove trailing part of `str` after `c`
 */
inline std::string rstrip(const std::string& str, char c)
{
  return str.substr(0, str.find_first_of(c));
}

/**
 * @brief Cast the inputString to the specified type.
 * @param inputString String to cast to the specified type.
 * @retval converted value if cast is successful
 * @retval std::nullopt otherwise
 */
template <typename T>
std::optional<T> lexicalCast(const std::string& inputString)
{
  T value;
  std::istringstream stream(inputString);
  stream >> value;
  if (stream.fail())
    return std::nullopt;
  return value;
}

/**
 * @brief Cast the inputString to a double, tolerating out of range exponents.
 *
 * Some programs write coordinates (or other values) with exponents a double
 * cannot represent, e.g. "2.61793E-500" or "-7.5467E-6000". The stream
 * extractor reports these as errors, which would otherwise abort reading an
 * entire file over a value that is effectively zero. Fall back to strtod for
 * the range error alone: underflow becomes zero and overflow is clamped to the
 * largest representable magnitude so that later arithmetic cannot see an
 * infinity. Anything the extractor rejects for another reason (including the
 * literals "nan" and "inf") is still an error.
 */
template <>
inline std::optional<double> lexicalCast(const std::string& inputString)
{
  double value;
  std::istringstream stream(inputString);
  stream >> value;
  // Whether the extractor accepts the literals "nan" and "inf" varies between
  // standard library implementations and versions -- libstdc++ rejects them,
  // and libc++ accepted them until recently -- so a non-finite result from it
  // cannot be trusted. Fall through to strtod, which tells a genuine
  // out-of-range exponent (ERANGE, clamped below) apart from a literal.
  if (!stream.fail() && std::isfinite(value))
    return value;

  const char* first = inputString.c_str();
  char* last = nullptr;
  errno = 0;
  value = std::strtod(first, &last);
  if (last == first || errno != ERANGE)
    return std::nullopt;

  if (std::isinf(value))
    value = (value > 0.0) ? std::numeric_limits<double>::max()
                          : std::numeric_limits<double>::lowest();
  return value;
}

/**
 * @brief Cast the inputString to the specified type.
 * @param inputString String to cast to the specified type.
 * @param ok Set to true on success, and false if the string could not be
 * converted to the specified type.
 */
template <typename T>
T lexicalCast(const std::string& inputString, bool& ok)
{
  if (auto value = lexicalCast<T>(inputString)) {
    ok = true;
    return *value;
  }
  ok = false;
  return {};
}

/**
 * @brief Cast the range to the specified type.
 * @param first Start of the range
 * @param last End of the range
 * @retval converted values if cast of ALL the elements are successful
 * @retval std::nullopt otherwise
 */
template <typename T, typename Iterator>
std::optional<std::vector<T>> lexicalCast(Iterator first, Iterator last)
{
  std::vector<T> values;
  for (; first != last; ++first) {
    if (auto value = lexicalCast<T>(*first)) {
      values.emplace_back(*value);
    } else {
      return std::nullopt;
    }
  }
  return values;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_UTILITIES_H
