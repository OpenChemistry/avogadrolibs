/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_UTILITIES_H
#define AVOGADRO_CORE_UTILITIES_H

#include "avogadrocoreexport.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
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
 *
 * For whitespace-separated text use splitWhitespace().
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
 * @brief Split @p input into tokens separated by runs of white space.
 * @param input The string to be split up.
 * @return A vector containing the tokens, never any empty ones.
 *
 * Unlike split(), which takes one delimiter character, any run of ' ', '\t',
 * '\r' or '\n' (the set trimmed() uses) separates tokens, so tabs and line
 * endings never end up inside them. split(s, ' ') leaves "2yn\n" as a token
 * and keeps "a\tb" whole; split() also keeps the empty field between adjacent
 * delimiters when skipEmpty is false, which suits delimited formats. Use
 * splitWhitespace() for free-format, whitespace-separated text such as
 * symbols, keywords and columns that may be separated by tabs.
 *
 * For example, "  -P   2yn \n" gives {"-P", "2yn"}, and "a\tb c" gives
 * {"a", "b", "c"} where split("a\tb c", ' ') gives {"a\tb", "c"}.
 */
inline std::vector<std::string> splitWhitespace(const std::string& input)
{
  constexpr const char* whitespace = " \t\r\n";
  std::vector<std::string> tokens;
  std::string::size_type start = input.find_first_not_of(whitespace);
  while (start != std::string::npos) {
    std::string::size_type end = input.find_first_of(whitespace, start);
    if (end == std::string::npos) {
      tokens.push_back(input.substr(start));
      break;
    }
    tokens.push_back(input.substr(start, end - start));
    start = input.find_first_not_of(whitespace, end);
  }
  return tokens;
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
 * @brief Lower-case the ASCII letters A-Z in @p input.
 *
 * Deliberately independent of the C locale, since it is used on file
 * contents: every other byte, including UTF-8 sequences, is left unchanged.
 */
inline std::string toLower(std::string input)
{
  for (auto& c : input) {
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c - 'A' + 'a');
  }
  return input;
}

/**
 * @brief Whether @p a and @p b are equal, ignoring the case of ASCII letters.
 * @param a First string to compare.
 * @param b Second string to compare.
 * @return True if the strings have the same length and differ at most in the
 * case of the letters A-Z, false otherwise.
 *
 * Like toLower(), this is independent of the C locale: every byte other than
 * A-Z, including UTF-8 sequences, must match exactly ("\xC3\x84" and
 * "\xC3\xA4", i.e. "Ä" and "ä", are different).
 */
inline bool caseInsensitiveEquals(const std::string& a, const std::string& b)
{
  if (a.size() != b.size())
    return false;
  for (std::string::size_type i = 0; i < a.size(); ++i) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z')
      x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z')
      y = static_cast<char>(y - 'A' + 'a');
    if (x != y)
      return false;
  }
  return true;
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
 * @brief Parse a floating-point number from [first, last) independent of the C
 * locale.
 * @param first Start of the text.
 * @param last One past the end of the text.
 * @param value Receives the number; unchanged if nothing was parsed.
 * @return Pointer one past the parsed number, or nullptr if no number was
 * parsed.
 *
 * Leading whitespace and a leading '+' are accepted; "nan" and "inf" are
 * rejected. A Fortran double precision exponent is read like an 'E' one
 * ("1.0D-03" is 0.001), but an exponent with no letter is not: "1-5" gives 1
 * and stops at the '-'. Values too small to represent become (signed) zero;
 * values too large are clamped to the largest finite magnitude, so a stray
 * exponent such as "2.61793E-500" does not discard a whole file.
 *
 * Qt sets the C locale from the environment, and strtod then expects the
 * user's decimal separator ("1,5" rather than "1.5" in a German locale). Use
 * these functions, not strtod or atof, for anything read from a file or from
 * another program.
 */
AVOGADROCORE_EXPORT const char* parseDouble(const char* first, const char* last,
                                            double& value);

/**
 * @brief Single precision version of parseDouble().
 *
 * The text is parsed directly as a float, so subnormal values such as
 * "9.293354777E-39" are accepted and are not rounded twice.
 */
AVOGADROCORE_EXPORT const char* parseFloat(const char* first, const char* last,
                                           float& value);

/**
 * @brief The byte order of binary data read from a file.
 */
enum class ByteOrder
{
  BigEndian,
  LittleEndian
};

/**
 * @brief Decode a 32-bit signed integer stored in a given byte order.
 *
 * The result does not depend on the host's byte order.
 *
 * @param data Must point at at least 4 readable bytes.
 * @param byteOrder The byte order of the stored value.
 */
AVOGADROCORE_EXPORT int32_t unpackInt32(const char* data, ByteOrder byteOrder);

/**
 * @brief Decode an IEEE 754 single precision float stored in a given byte
 * order.
 *
 * The bits are copied, not converted, so -0.0, denormals, infinities and NaNs
 * are exact.
 *
 * @param data Must point at at least 4 readable bytes.
 * @param byteOrder The byte order of the stored value.
 */
AVOGADROCORE_EXPORT float unpackFloat(const char* data, ByteOrder byteOrder);

/**
 * @brief Double precision version of unpackFloat().
 *
 * @param data Must point at at least 8 readable bytes.
 */
AVOGADROCORE_EXPORT double unpackDouble(const char* data, ByteOrder byteOrder);

/**
 * @brief Whether @p pos ends a number that was parsed up to @p last.
 *
 * A number is complete at the end of the text, or before a character that
 * could not continue it: anything except an ASCII letter, digit, '.', '+'
 * or '-'. This rejects "1.5abc", "1.2.3", "1.5D" and the letterless Fortran
 * exponents "1-5" and "1.5+2" (which a stream extractor would silently read
 * as 1.0 or 1.5 with some standard libraries and refuse with others), while
 * still accepting "1.5 2.0" (the first token), "1.5," and "1.5)". Fortran
 * "1.0D-03" is a number: parseDouble() reads the whole of it.
 */
inline bool endsNumber(const char* pos, const char* last)
{
  if (pos == last)
    return true;
  const char c = *pos;
  const bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  const bool digit = c >= '0' && c <= '9';
  return !(letter || digit || c == '.' || c == '+' || c == '-');
}

/**
 * @brief Cast the inputString to a double, independent of the C locale.
 *
 * Uses parseDouble(), so exponents a double cannot represent (e.g.
 * "2.61793E-500") give zero or the largest finite magnitude rather than an
 * error, and the literals "nan" and "inf" are rejected. The number must be
 * followed by the end of the string or by a character that cannot continue it
 * (see endsNumber()).
 */
template <>
inline std::optional<double> lexicalCast(const std::string& inputString)
{
  const char* first = inputString.data();
  const char* last = first + inputString.size();
  double value = 0.0;
  const char* end = parseDouble(first, last, value);
  if (end == nullptr || !endsNumber(end, last))
    return std::nullopt;
  return value;
}

/**
 * @brief Cast the inputString to a float, independent of the C locale.
 *
 * As for the double overload. The text is parsed directly as a float, so the
 * decaying tail of a density or an orbital written past FLT_MIN (e.g.
 * "1.505124610E-39") is kept as a subnormal, and a magnitude beyond float is
 * clamped rather than becoming an infinity.
 */
template <>
inline std::optional<float> lexicalCast(const std::string& inputString)
{
  const char* first = inputString.data();
  const char* last = first + inputString.size();
  float value = 0.0f;
  const char* end = parseFloat(first, last, value);
  if (end == nullptr || !endsNumber(end, last))
    return std::nullopt;
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
