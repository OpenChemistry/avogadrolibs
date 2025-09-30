/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_UTILITIES_H
#define AVOGADRO_CORE_UTILITIES_H

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace Avogadro::Core {

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
 */
template <typename T>
T lexicalCast(const std::string& inputString)
{
  T value;
  std::istringstream(inputString) >> value;
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
  T value;
  std::istringstream stream(inputString);
  stream >> value;
  ok = !stream.fail();
  return value;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_UTILITIES_H
