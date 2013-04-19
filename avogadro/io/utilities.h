/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_UTILITIES_H
#define AVOGADRO_IO_UTILITIES_H

#include <string>
#include <vector>
#include <sstream>

namespace Avogadro {
namespace Io {

/**
 * @brief Split the supplied @p string by the @p delimiter.
 * @param string The string to be split up.
 * @param delimiter The delimiter to split the string by.
 * @param skipEmpty If true any empty items will be skipped.
 * @return A vector containing the items.
 */
inline std::vector<std::string> split(const std::string &string, char delimiter,
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
inline bool contains(const std::string &input, const std::string &search)
{
  size_t found = input.find(search);
  return found != std::string::npos;
}

/**
 * @brief Trim a string of whitespace from the left and right.
 */
inline std::string trimmed(const std::string &input)
{
  size_t start = input.find_first_not_of(" \n\r\t");
  size_t end = input.find_last_not_of(" \n\r\t");
  return input.substr(start, end - start + 1);
}

/**
 * @brief Cast the inputString to the specified type.
 * @param inputString String to cast to the specified type.
 */
template<typename T> T lexicalCast(const std::string &inputString)
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
template<typename T> T lexicalCast(const std::string &inputString, bool &ok)
{
  T value;
  std::istringstream stream(inputString);
  stream >> value;
  ok = !stream.fail();
  return value;
}

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_UTILITIES_H
