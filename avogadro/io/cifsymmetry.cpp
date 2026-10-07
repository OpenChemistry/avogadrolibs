/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cifsymmetry.h"

#include <avogadro/core/spacegroups.h>

#include <algorithm>
#include <cctype>
#include <cstddef>

namespace Avogadro::Io {

namespace {

bool isSpace(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
         c == '\v';
}

std::string lowerCase(const std::string& s)
{
  std::string result = s;
  std::transform(result.begin(), result.end(), result.begin(), [](char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  });
  return result;
}

bool startsWith(const std::string& s, const char* prefix)
{
  std::size_t i = 0;
  for (; prefix[i] != '\0'; ++i) {
    if (i >= s.size() || s[i] != prefix[i])
      return false;
  }
  return true;
}

enum class TokenType
{
  End,   // no more input
  Tag,   // _tag_name
  Loop,  // loop_
  Data,  // data_name
  Other, // save_, global_, stop_: they end a loop
  Value  // anything else, including quoted strings and text fields
};

struct Token
{
  TokenType type = TokenType::End;
  std::string text; // lower case for everything but values
  bool quoted = false;
};

// Splits CIF text into tokens: comments are skipped, quoted strings and
// semicolon text fields are single value tokens.
class CifTokenizer
{
public:
  explicit CifTokenizer(const std::string& text) : m_text(text) {}

  Token next()
  {
    Token token;
    skipSpaceAndComments();
    if (m_pos >= m_text.size())
      return token;

    char c = m_text[m_pos];
    if (c == ';' && atLineStart(m_pos)) {
      // a text field runs to the next line that starts with a semicolon
      std::size_t end = m_text.find("\n;", m_pos + 1);
      if (end == std::string::npos)
        return stop(); // never closed
      token.type = TokenType::Value;
      token.quoted = true;
      token.text = m_text.substr(m_pos + 1, end - m_pos - 1);
      m_pos = end + 2;
      return token;
    }

    if (c == '\'' || c == '"') {
      // a quote closes when it is followed by whitespace; a string does not
      // continue past the end of the line
      std::size_t i = m_pos + 1;
      while (i < m_text.size() && m_text[i] != '\n') {
        if (m_text[i] == c &&
            (i + 1 >= m_text.size() || isSpace(m_text[i + 1])))
          break;
        ++i;
      }
      if (i >= m_text.size() || m_text[i] != c)
        return stop(); // never closed
      token.type = TokenType::Value;
      token.quoted = true;
      token.text = m_text.substr(m_pos + 1, i - m_pos - 1);
      m_pos = i + 1;
      return token;
    }

    std::size_t end = m_pos;
    while (end < m_text.size() && !isSpace(m_text[end]))
      ++end;
    std::string word = m_text.substr(m_pos, end - m_pos);
    m_pos = end;

    std::string lower = lowerCase(word);
    if (lower[0] == '_') {
      token.type = TokenType::Tag;
      token.text = lower;
    } else if (lower == "loop_") {
      token.type = TokenType::Loop;
    } else if (startsWith(lower, "data_")) {
      token.type = TokenType::Data;
    } else if (startsWith(lower, "save_") || startsWith(lower, "global_") ||
               lower == "stop_") {
      token.type = TokenType::Other;
    } else {
      token.type = TokenType::Value;
      token.text = word;
    }
    return token;
  }

private:
  // The input is malformed from here on: there is nothing more to read.
  Token stop()
  {
    m_pos = m_text.size();
    return Token();
  }

  bool atLineStart(std::size_t pos) const
  {
    return pos == 0 || m_text[pos - 1] == '\n';
  }

  void skipSpaceAndComments()
  {
    while (m_pos < m_text.size()) {
      char c = m_text[m_pos];
      if (isSpace(c)) {
        ++m_pos;
      } else if (c == '#') {
        while (m_pos < m_text.size() && m_text[m_pos] != '\n')
          ++m_pos;
      } else {
        break;
      }
    }
  }

  const std::string& m_text;
  std::size_t m_pos = 0;
};

bool isOperationTag(const std::string& tag)
{
  return tag == "_symmetry_equiv_pos_as_xyz" ||
         tag == "_space_group_symop_operation_xyz" ||
         tag == "_space_group_symop.operation_xyz";
}

bool isHallTag(const std::string& tag)
{
  return tag == "_symmetry_space_group_name_hall" ||
         tag == "_space_group_name_hall" || tag == "_space_group.name_hall";
}

// Collapse runs of white space to one space and trim the ends, and write a
// double quote as the table does.
std::string normalizeHallSymbol(const std::string& symbol)
{
  std::string result;
  bool pendingSpace = false;
  for (char c : symbol) {
    if (isSpace(c)) {
      pendingSpace = !result.empty();
      continue;
    }
    if (pendingSpace)
      result.push_back(' ');
    pendingSpace = false;
    result.push_back(c == '"' ? '=' : c);
  }
  return result;
}

// The hall number whose Hall symbol is this one, with no other spellings.
unsigned short hallFromHallSymbol(const std::string& symbol)
{
  std::string normalized = normalizeHallSymbol(symbol);
  if (normalized.empty())
    return 0;
  unsigned short hall = Core::SpaceGroups::hallNumber(normalized);
  if (hall == 0)
    return 0;
  // hallNumber() also accepts the international symbols and numbers. A
  // symbol that is not this entry's Hall symbol could be another group's.
  return normalized == Core::SpaceGroups::hallSymbol(hall) ? hall : 0;
}

// The operations in the values of a one-column loop. Unquoted operations may
// have been written with spaces ("x, y, z"), which split them into several
// tokens; join those until there are three coordinates.
void addSingleColumnOperations(const std::vector<Token>& values,
                               std::vector<std::string>& operations)
{
  std::string pending;
  auto flush = [&]() {
    if (!pending.empty())
      operations.push_back(pending);
    pending.clear();
  };
  for (const Token& value : values) {
    if (value.quoted) {
      flush();
      operations.push_back(value.text);
      continue;
    }
    pending += value.text;
    if (std::count(pending.begin(), pending.end(), ',') >= 2 &&
        pending.back() != ',')
      flush();
  }
  flush();
}

} // namespace

CifSymmetry readCifSymmetry(const std::string& cifText)
{
  CifSymmetry result;
  CifTokenizer tokenizer(cifText);

  bool haveOperations = false;
  bool haveHall = false;
  bool seenData = false;

  Token token = tokenizer.next();
  while (token.type != TokenType::End) {
    if (token.type == TokenType::Data) {
      // only the first block is read
      if (seenData)
        break;
      seenData = true;
      token = tokenizer.next();
      continue;
    }

    if (token.type == TokenType::Tag) {
      // a tag and its value
      std::string tag = token.text;
      token = tokenizer.next();
      if (token.type != TokenType::Value)
        continue; // no value: the token is handled next
      if (isOperationTag(tag) && !haveOperations) {
        result.operations.push_back(token.text);
        haveOperations = true;
      } else if (isHallTag(tag) && !haveHall) {
        result.hallSymbol = normalizeHallSymbol(token.text);
        haveHall = true;
      }
      token = tokenizer.next();
      continue;
    }

    if (token.type == TokenType::Loop) {
      std::vector<std::string> tags;
      token = tokenizer.next();
      while (token.type == TokenType::Tag) {
        tags.push_back(token.text);
        token = tokenizer.next();
      }

      // the column that holds the operations, if any
      std::size_t column = tags.size();
      if (!haveOperations) {
        for (std::size_t i = 0; i < tags.size(); ++i) {
          if (isOperationTag(tags[i])) {
            column = i;
            break;
          }
        }
      }
      const bool wanted = column < tags.size();

      // the values run until the next tag, loop_, data_ block, etc.
      std::vector<Token> values;
      while (token.type == TokenType::Value) {
        if (wanted)
          values.push_back(token);
        token = tokenizer.next();
      }

      if (wanted) {
        if (tags.size() == 1) {
          addSingleColumnOperations(values, result.operations);
          haveOperations = true;
        } else if (values.size() % tags.size() == 0) {
          for (std::size_t i = column; i < values.size(); i += tags.size())
            result.operations.push_back(values[i].text);
          haveOperations = true;
        }
        // a loop that does not fill its rows is malformed: use nothing
      }
      continue; // the token that ended the loop is handled next
    }

    // a value without a tag, or save_ and the like
    token = tokenizer.next();
  }

  result.hallFromOperations =
    Core::SpaceGroups::hallNumberFromTransforms(result.operations);
  result.hallFromSymbol = hallFromHallSymbol(result.hallSymbol);
  return result;
}

} // namespace Avogadro::Io
