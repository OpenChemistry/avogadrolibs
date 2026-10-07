/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spacegroups.h"

#include "crystaltools.h"
#include "molecule.h"
#include "spacegroupdata.h"
#include "unitcell.h"
#include "utilities.h"

#include <algorithm> // for std::count()
#include <array>
#include <cctype> // for isdigit(), tolower()
#include <cmath>  // for floor()
#include <iostream>
#include <string>
#include <vector>

namespace Avogadro::Core {

namespace {

// The hall numbers run from 1 to 530; the table has an empty entry 0.
constexpr unsigned short lastHallNumber = 530;

// The "international" column holds the short symbol followed by equivalent
// spellings, e.g. "P 2_1/c = P 1 2_1/c 1".
struct SymbolEntry
{
  std::string full;                 // normalized international_full
  std::vector<std::string> aliases; // normalized parts of international
  std::string compact;              // international_short, e.g. "P2_1/c"
  std::string setting;
  unsigned short number = 0; // international table number
};

std::string trimWhitespace(const std::string& s)
{
  const char* whitespace = " \t\r\n";
  std::string::size_type first = s.find_first_not_of(whitespace);
  if (first == std::string::npos)
    return std::string();
  std::string::size_type last = s.find_last_not_of(whitespace);
  return s.substr(first, last - first + 1);
}

std::vector<std::string> splitTokens(const std::string& s)
{
  std::vector<std::string> tokens;
  std::string current;
  for (char c : s) {
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      if (!current.empty())
        tokens.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  if (!current.empty())
    tokens.push_back(current);
  return tokens;
}

// The spelling of a Hall symbol in the table: runs of white space collapsed to
// one space, the ends trimmed, and '=' where a file has a double quote.
std::string normalizeHallSymbol(const std::string& symbol)
{
  std::string result;
  for (const auto& token : splitTokens(symbol)) {
    if (!result.empty())
      result.push_back(' ');
    result += token;
  }
  std::replace(result.begin(), result.end(), '"', '=');
  return result;
}

// A screw axis written without the underscore: "21", "63", "41/a", ...
// Only N in {2, 3, 4, 6} with 1 <= M < N is a screw axis N_M.
std::string normalizeScrewAxis(const std::string& token)
{
  if (token.size() >= 2 && (token.size() == 2 || token[2] == '/') &&
      std::isdigit(static_cast<unsigned char>(token[0])) &&
      std::isdigit(static_cast<unsigned char>(token[1]))) {
    int n = token[0] - '0';
    int m = token[1] - '0';
    if ((n == 2 || n == 3 || n == 4 || n == 6) && m >= 1 && m < n)
      return std::string(1, token[0]) + "_" + token[1] + token.substr(2);
  }
  return token;
}

// Spelling shared by the table and the symbols found in files:
//  - screw axes get their underscore ("P 63 m c" -> "P 6_3 m c")
//  - in a cubic symbol with a single plane letter in the second position, the
//    three-fold axis is written "-3" ("I m 3 m" -> "I m -3 m"). Both the
//    pre-1983 notation and this table use a plain "3" for these centro-
//    symmetric groups, which can never be confused with a rotation group
//    because those have a digit (2, 4, -4, 4_1, ...) in the second position.
std::string normalizeSymbol(const std::string& symbol)
{
  std::vector<std::string> tokens = splitTokens(symbol);
  for (auto& token : tokens)
    token = normalizeScrewAxis(token);

  if (tokens.size() >= 3 && (tokens[2] == "3" || tokens[2] == "-3") &&
      tokens[1].size() == 1 &&
      std::string("mnabcd").find(tokens[1][0]) != std::string::npos) {
    tokens[2] = "-3";
  }

  std::string result;
  for (const auto& token : tokens) {
    if (!result.empty())
      result.push_back(' ');
    result += token;
  }
  return result;
}

const std::vector<SymbolEntry>& symbolTable()
{
  static const std::vector<SymbolEntry> table = [] {
    std::vector<SymbolEntry> entries(531);
    for (unsigned short i = 1; i < 531; ++i) {
      SymbolEntry& entry = entries[i];
      entry.full = normalizeSymbol(space_group_international_full[i]);
      entry.compact = space_group_international_short[i];
      entry.setting = space_group_setting[i];
      entry.number = space_group_international_number[i];

      const std::string international = space_group_international[i];
      const std::string separator = " = ";
      std::string::size_type start = 0;
      while (true) {
        std::string::size_type pos = international.find(separator, start);
        entry.aliases.push_back(normalizeSymbol(international.substr(
          start, pos == std::string::npos ? std::string::npos : pos - start)));
        if (pos == std::string::npos)
          break;
        start = pos + separator.size();
      }
    }
    return entries;
  }();
  return table;
}

// Settings that select an origin choice or a hexagonal/rhombohedral axis
// system ("1", "2", "1cab", "H", "R", ...). Unlike the cell choices of the
// monoclinic groups, these have no conventional default we may assume.
bool isOriginOrAxisSetting(const std::string& setting)
{
  return !setting.empty() && (setting[0] == '1' || setting[0] == '2' ||
                              setting == "H" || setting == "R");
}

bool equalsIgnoreCase(const std::string& a, const std::string& b)
{
  if (a.size() != b.size())
    return false;
  for (std::string::size_type i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i])))
      return false;
  }
  return true;
}

// Exact comparison against the strings in the table
unsigned short exactHallNumber(const std::string& sg)
{
  const unsigned short hall_count = 531; // 530 but first one is empty

  // space_group_hall_symbol
  for (unsigned short i = 0; i < hall_count; ++i) {
    if (sg == space_group_hall_symbol[i])
      return i;
  }

  // space_group_international
  for (unsigned short i = 0; i < hall_count; ++i) {
    if (sg == space_group_international[i])
      return i;
  }

  // space_group_international_short
  for (unsigned short i = 0; i < hall_count; ++i) {
    if (sg == space_group_international_short[i])
      return i;
  }

  // space_group_international_full
  for (unsigned short i = 0; i < hall_count; ++i) {
    if (sg == space_group_international_full[i])
      return i;
  }

  return 0;
}

struct Resolved
{
  unsigned short hall = 0;
  unsigned short number = 0;
};

// Parse a bare international table number, e.g. "74".
bool parseBareNumber(const std::string& s, unsigned short& number)
{
  if (s.empty() || s.size() > 3)
    return false;
  unsigned int value = 0;
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c)))
      return false;
    value = value * 10 + static_cast<unsigned int>(c - '0');
  }
  if (value < 1 || value > 230)
    return false;
  number = static_cast<unsigned short>(value);
  return true;
}

// Find the Hall numbers that a (setting-less) symbol can refer to. The full
// symbol is the most specific, then the alternative spellings, then the
// compact one. The first tier with a match wins.
std::vector<unsigned short> matchSymbol(const std::string& symbol)
{
  const auto& table = symbolTable();
  const std::string key = normalizeSymbol(symbol);
  std::vector<unsigned short> matches;
  if (key.empty())
    return matches;

  for (unsigned short i = 1; i < 531; ++i) {
    if (table[i].full == key)
      matches.push_back(i);
  }
  if (!matches.empty())
    return matches;

  for (unsigned short i = 1; i < 531; ++i) {
    for (const auto& alias : table[i].aliases) {
      if (alias == key) {
        matches.push_back(i);
        break;
      }
    }
  }
  if (!matches.empty())
    return matches;

  for (unsigned short i = 1; i < 531; ++i) {
    if (table[i].compact == symbol)
      matches.push_back(i);
  }
  return matches;
}

// Everything but the exact matches: bare numbers, screw axes without
// underscores, setting suffixes (":H", ":1"), old cubic notation.
Resolved resolveSymbol(const std::string& sg)
{
  Resolved result;
  const auto& table = symbolTable();

  unsigned short bare = 0;
  if (parseBareNumber(sg, bare)) {
    result.number = bare;
    unsigned short count = 0;
    for (unsigned short i = 1; i < 531; ++i) {
      if (table[i].number == bare) {
        ++count;
        result.hall = i;
      }
    }
    // Several settings (axes, cell or origin choice): do not guess one
    if (count != 1)
      result.hall = 0;
    return result;
  }

  // a trailing setting, e.g. "F d -3 m :2" or "R -3 m:H"
  std::string symbol = sg;
  std::string setting;
  std::string::size_type colon = sg.rfind(':');
  if (colon != std::string::npos) {
    symbol = trimWhitespace(sg.substr(0, colon));
    setting = trimWhitespace(sg.substr(colon + 1));
  }

  std::vector<unsigned short> matches = matchSymbol(symbol);
  if (matches.empty())
    return result;

  // the symbol has to agree on the table number, or it is not a symbol
  unsigned short number = table[matches.front()].number;
  for (unsigned short hall : matches) {
    if (table[hall].number != number)
      return result;
  }
  result.number = number;

  if (!setting.empty()) {
    std::vector<unsigned short> filtered;
    for (unsigned short hall : matches) {
      if (equalsIgnoreCase(table[hall].setting, setting))
        filtered.push_back(hall);
    }
    if (filtered.size() == 1)
      result.hall = filtered.front();
    return result;
  }

  if (matches.size() == 1) {
    result.hall = matches.front();
    return result;
  }

  // Several settings share this symbol. Cell/axis choices of the same symbol
  // (e.g. "P 2_1/c") have a conventional default, which is the first one in
  // the table. An origin choice or hexagonal/rhombohedral axes do not.
  for (unsigned short hall : matches) {
    if (isOriginOrAxisSetting(table[hall].setting))
      return result;
  }
  result.hall = matches.front();
  return result;
}

} // namespace

unsigned short SpaceGroups::hallNumber(const std::string& spaceGroup)
{
  // some files use " instead of = for the space group symbol
  std::string sg = trimWhitespace(spaceGroup);
  std::replace(sg.begin(), sg.end(), '"', '=');

  unsigned short hall = exactHallNumber(sg);
  if (hall != 0)
    return hall;

  return resolveSymbol(sg).hall;
}

unsigned short SpaceGroups::hallNumberFromHallSymbol(
  const std::string& hallSymbol)
{
  const std::string symbol = normalizeHallSymbol(hallSymbol);
  if (symbol.empty())
    return 0;

  for (unsigned short i = 1; i <= lastHallNumber; ++i) {
    if (symbol == space_group_hall_symbol[i])
      return i;
  }
  return 0;
}

unsigned short SpaceGroups::internationalNumberFromString(
  const std::string& spaceGroup)
{
  std::string sg = trimWhitespace(spaceGroup);
  std::replace(sg.begin(), sg.end(), '"', '=');

  unsigned short hall = exactHallNumber(sg);
  if (hall != 0)
    return internationalNumber(hall);

  return resolveSymbol(sg).number;
}

const char* SpaceGroups::internationalNumberKey()
{
  return "spaceGroup.internationalNumber";
}

CrystalSystem SpaceGroups::crystalSystem(unsigned short hallNumber)
{
  if (hallNumber == 1 || hallNumber == 2)
    return Triclinic;
  if (hallNumber >= 3 && hallNumber <= 107)
    return Monoclinic;
  if (hallNumber >= 108 && hallNumber <= 348)
    return Orthorhombic;
  if (hallNumber >= 349 && hallNumber <= 429)
    return Tetragonal;
  if (hallNumber >= 430 && hallNumber <= 461) {
    // 14 of these are rhombohedral and the rest are trigonal
    switch (hallNumber) {
      case 433:
      case 434:
      case 436:
      case 437:
      case 444:
      case 445:
      case 450:
      case 451:
      case 452:
      case 453:
      case 458:
      case 459:
      case 460:
      case 461:
        return Rhombohedral;
      default:
        return Trigonal;
    }
  }
  if (hallNumber >= 462 && hallNumber <= 488)
    return Hexagonal;
  if (hallNumber >= 489 && hallNumber <= 530)
    return Cubic;
  // hallNumber must be 0 or > 531
  return None;
  // for (unsigned short i = 0; i < hallNumberCount; ++i)
}

unsigned short SpaceGroups::internationalNumber(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_number[hallNumber];
  else
    return space_group_international_number[0];
}

const char* SpaceGroups::schoenflies(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_schoenflies[hallNumber];
  else
    return space_group_schoenflies[0];
}

const char* SpaceGroups::hallSymbol(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_hall_symbol[hallNumber];
  else
    return space_group_hall_symbol[0];
}

const char* SpaceGroups::international(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international[hallNumber];
  else
    return space_group_international[0];
}

const char* SpaceGroups::internationalFull(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_full[hallNumber];
  else
    return space_group_international_full[0];
}

const char* SpaceGroups::internationalShort(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_international_short[hallNumber];
  else
    return space_group_international_short[0];
}

const char* SpaceGroups::setting(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_setting[hallNumber];
  else
    return space_group_setting[0];
}

unsigned short SpaceGroups::transformsCount(unsigned short hallNumber)
{
  if (hallNumber <= 530) {
    std::string s = transformsString(hallNumber);
    return std::count(s.begin(), s.end(), ' ') + 1;
  } else {
    return 0;
  }
}

namespace {

// One term of a coordinate expression such as "1/2-x": either a signed
// fractional coordinate (variable 0, 1 or 2 for x, y, z) or a constant.
struct CoordinateTerm
{
  int variable = -1; // 0, 1, 2 for x, y, z; -1 for a constant
  bool negative = false;
  Real constant = 0.0; // signed value, used for constants only
};

// Read an unsigned number: "1", "0.5", ".25", "1/2" (a ratio of two integers).
bool readCoordinateNumber(const std::string& s, std::size_t& i, Real& value)
{
  Real numerator = 0.0;
  bool haveDigits = false;
  while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
    numerator = numerator * 10.0 + (s[i] - '0');
    haveDigits = true;
    ++i;
  }
  if (i < s.size() && s[i] == '.') {
    ++i;
    Real scale = 0.1;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
      numerator += scale * (s[i] - '0');
      scale *= 0.1;
      haveDigits = true;
      ++i;
    }
  }
  if (!haveDigits)
    return false;

  Real denominator = 1.0;
  if (i < s.size() && s[i] == '/') {
    ++i;
    denominator = 0.0;
    bool haveDenominator = false;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
      denominator = denominator * 10.0 + (s[i] - '0');
      haveDenominator = true;
      ++i;
    }
    if (!haveDenominator || denominator == 0.0)
      return false;
  }
  value = numerator / denominator;
  return true;
}

// Split a coordinate expression ("x", "-y+1/2", "x-y", "0.5+z") into terms.
// Letters are case insensitive. Anything else is rejected, including a number
// that is directly followed by a letter ("2x"), which is not a translation.
bool parseCoordinate(const std::string& coordinate,
                     std::vector<CoordinateTerm>& terms)
{
  terms.clear();
  std::size_t i = 0;
  while (i < coordinate.size()) {
    bool isNeg = false;
    if (coordinate[i] == '-' || coordinate[i] == '+') {
      isNeg = (coordinate[i] == '-');
      ++i;
      if (i >= coordinate.size())
        return false;
    }

    CoordinateTerm term;
    term.negative = isNeg;
    char c = coordinate[i];
    if (std::isdigit(static_cast<unsigned char>(c)) || c == '.') {
      Real value = 0.0;
      if (!readCoordinateNumber(coordinate, i, value))
        return false;
      if (i < coordinate.size()) {
        char next = static_cast<char>(
          std::tolower(static_cast<unsigned char>(coordinate[i])));
        if (next == 'x' || next == 'y' || next == 'z')
          return false;
      }
      term.constant = isNeg ? -value : value;
    } else {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      if (c == 'x')
        term.variable = 0;
      else if (c == 'y')
        term.variable = 1;
      else if (c == 'z')
        term.variable = 2;
      else
        return false;
      ++i;
    }
    terms.push_back(term);
  }
  return !terms.empty();
}

Real readTransformCoordinate(const std::string& coordinate, const Vector3& v)
{
  std::vector<CoordinateTerm> terms;
  if (!parseCoordinate(coordinate, terms)) {
    std::cerr << "In " << __FUNCTION__ << ", error reading string: '"
              << coordinate << "'\n";
    return 0;
  }

  Real ret = 0.0;
  for (const CoordinateTerm& term : terms) {
    if (term.variable < 0)
      ret += term.constant;
    else
      ret += term.negative ? -1.0 * v[term.variable] : v[term.variable];
  }
  return ret;
}

Vector3 getSingleTransform(const std::string& transform, const Vector3& v)
{
  Vector3 ret = Vector3::Zero();
  std::vector<std::string> coordinates = split(transform, ',');

  // This should be 3 in size. Something very bad happened if it is not.
  if (coordinates.size() != 3) {
    std::cerr << "In " << __FUNCTION__ << ", error reading string: '"
              << transform << "'\n";
    return ret;
  }

  ret[0] = readTransformCoordinate(coordinates[0], v);
  ret[1] = readTransformCoordinate(coordinates[1], v);
  ret[2] = readTransformCoordinate(coordinates[2], v);
  return ret;
}

// A symmetry operation reduced to what identifies it: the integer rotation
// part (row-major) and the translation modulo one in twelfths. Every
// translation in the table is a multiple of 1/12 (halves, thirds, quarters,
// sixths).
struct SymmetryOperation
{
  std::array<signed char, 9> rotation = {};
  std::array<signed char, 3> translation = {};

  bool operator<(const SymmetryOperation& other) const
  {
    return std::tie(rotation, translation) <
           std::tie(other.rotation, other.translation);
  }
  bool operator==(const SymmetryOperation& other) const
  {
    return std::tie(rotation, translation) ==
           std::tie(other.rotation, other.translation);
  }
};

// Decimals such as 0.33, 0.3333 and 0.6667 are accepted when they are this
// close to a multiple of 1/12. Neighboring multiples are 0.083 apart.
constexpr Real operationTranslationTolerance = 1.0e-2;

// Parse "x,y,z"-style text. Quotes and whitespace are ignored. Returns false
// if the text is not an operation made of three coordinate expressions with
// every translation within tolerance of a multiple of 1/12.
bool parseSymmetryOperation(const std::string& text, SymmetryOperation& op)
{
  std::string s;
  s.reserve(text.size());
  for (char c : text) {
    if (c == '\'' || c == '"' || std::isspace(static_cast<unsigned char>(c)))
      continue;
    s.push_back(c);
  }

  std::vector<std::string> coordinates = split(s, ',', false);
  if (coordinates.size() != 3)
    return false;

  std::vector<CoordinateTerm> terms;
  for (int row = 0; row < 3; ++row) {
    if (!parseCoordinate(coordinates[row], terms))
      return false;

    int rotation[3] = { 0, 0, 0 };
    Real translation = 0.0;
    for (const CoordinateTerm& term : terms) {
      if (term.variable < 0)
        translation += term.constant;
      else
        rotation[term.variable] += term.negative ? -1 : 1;
    }

    // Every constant must be a multiple of 1/12, give or take rounding in the
    // file. Reduce it modulo one, in twelfths.
    Real twelfths = translation * 12.0;
    Real nearest = std::round(twelfths);
    if (std::abs(nearest) > 1.0e6 ||
        std::abs(twelfths - nearest) > 12.0 * operationTranslationTolerance)
      return false;
    long reduced = static_cast<long>(nearest) % 12;
    if (reduced < 0)
      reduced += 12;

    for (int column = 0; column < 3; ++column) {
      if (rotation[column] < -2 || rotation[column] > 2)
        return false;
      op.rotation[row * 3 + column] =
        static_cast<signed char>(rotation[column]);
    }
    op.translation[row] = static_cast<signed char>(reduced);
  }
  return true;
}

// Sort and remove repeated operations so sets can be compared.
void normalizeOperations(std::vector<SymmetryOperation>& ops)
{
  std::sort(ops.begin(), ops.end());
  ops.erase(std::unique(ops.begin(), ops.end()), ops.end());
}

// The operations of every table entry, parsed once with the same grammar that
// is used for the input.
const std::vector<std::vector<SymmetryOperation>>& tableOperations()
{
  static const std::vector<std::vector<SymmetryOperation>> table = [] {
    std::vector<std::vector<SymmetryOperation>> result(lastHallNumber + 1);
    for (unsigned short hall = 1; hall <= lastHallNumber; ++hall) {
      for (const std::string& text : split(space_group_transforms[hall], ' ')) {
        SymmetryOperation op;
        if (parseSymmetryOperation(text, op))
          result[hall].push_back(op);
      }
      normalizeOperations(result[hall]);
    }
    return result;
  }();
  return table;
}

} // namespace

unsigned short SpaceGroups::hallNumberFromTransforms(
  const std::vector<std::string>& operations)
{
  if (operations.empty())
    return 0;

  std::vector<SymmetryOperation> ops;
  ops.reserve(operations.size());
  for (const std::string& text : operations) {
    SymmetryOperation op;
    if (!parseSymmetryOperation(text, op))
      return 0;
    ops.push_back(op);
  }
  normalizeOperations(ops);

  // Entries that share one operation set (the three pairs of origin choices
  // of group 68 that have the same Hall symbol) are indistinguishable by their
  // operations; the first, lowest numbered, is the answer.
  const auto& table = tableOperations();
  for (unsigned short hall = 1; hall <= lastHallNumber; ++hall) {
    if (table[hall] == ops)
      return hall;
  }
  return 0;
}

Array<Vector3> SpaceGroups::getTransforms(unsigned short hallNumber,
                                          const Vector3& v)
{
  if (hallNumber == 0 || hallNumber > 530)
    return Array<Vector3>();

  Array<Vector3> ret;

  std::string transformsStr = transformsString(hallNumber);
  // These transforms are separated by spaces
  std::vector<std::string> transforms = split(transformsStr, ' ');

  for (auto& transform : transforms)
    ret.push_back(getSingleTransform(transform, v));

  return ret;
}

void SpaceGroups::fillUnitCell(Molecule& mol, unsigned short hallNumber,
                               double cartTol, bool wrapToCell, bool allCopies)
{
  if (!mol.unitCell())
    return;
  UnitCell* uc = mol.unitCell();

  Array<unsigned char> atomicNumbers = mol.atomicNumbers();
  Array<Vector3> positions = mol.atomPositions3d();
  Index numAtoms = mol.atomCount();

  // We are going to loop through the original atoms. That is why
  // we have numAtoms cached instead of using atomCount().
  for (Index i = 0; i < numAtoms; ++i) {
    unsigned char atomicNum = atomicNumbers[i];
    Vector3 pos = uc->toFractional(positions[i]);

    Array<Vector3> newAtoms = getTransforms(hallNumber, pos);

    // We skip 0 because it is the original atom.
    for (Index j = 1; j < newAtoms.size(); ++j) {
      // The new atoms are in fractional coordinates. Convert to cartesian.
      Vector3 newCandidate = uc->toCartesian(newAtoms[j]);
      // if we are wrapping to the cell, we need to wrap the new atom
      if (wrapToCell)
        newCandidate = uc->wrapCartesian(newCandidate);

      // If there is already any atom in this location within a
      // certain tolerance, do not add the atom.
      bool atomAlreadyPresent = false;
      for (Index k = 0; k < mol.atomCount(); k++) {
        Real distance = uc->distance(mol.atomPosition3d(k), newCandidate);
        if (distance <= cartTol) {
          atomAlreadyPresent = true;
          break; // no need to keep looking
        }
      }

      // If there is already an atom present here, just continue
      if (atomAlreadyPresent)
        continue;

      // If we got this far, add the atom!
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(newCandidate);
    }
  }

  // Now we generate any copies on the unit boundary
  if (allCopies)
    fillTranslationalCopies(mol, cartTol);
  else {
    // Remove atoms with fractional coordinates near 1.0 only if a
    // translational duplicate exists near 0.0 (same element, wrapped
    // fractional coords within tolerance). If no duplicate exists, wrap
    // the coordinate to 0.0 instead of deleting.
    const double fracTol = 0.001;
    std::vector<Index> toRemove;
    for (Index i = 0; i < mol.atomCount(); ++i) {
      Vector3 frac = uc->toFractional(mol.atomPositions3d()[i]);
      bool nearBoundary = false;
      for (Index j = 0; j < 3; ++j) {
        if (std::abs(frac[j] - 1.0) < fracTol) {
          nearBoundary = true;
          break;
        }
      }
      if (!nearBoundary)
        continue;

      // Build the wrapped version (1.0 -> 0.0)
      Vector3 wrapped = frac;
      for (Index j = 0; j < 3; ++j) {
        if (std::abs(wrapped[j] - 1.0) < fracTol)
          wrapped[j] = 0.0;
      }
      Vector3 wrappedCart = uc->toCartesian(wrapped);

      // Check if a different atom of the same element exists at the
      // wrapped position
      bool hasDuplicate = false;
      unsigned char atomicNum = mol.atomicNumber(i);
      for (Index k = 0; k < mol.atomCount(); ++k) {
        if (k == i)
          continue;
        if (mol.atomicNumber(k) != atomicNum)
          continue;
        if (uc->distance(mol.atomPosition3d(k), wrappedCart) < cartTol) {
          hasDuplicate = true;
          break;
        }
      }

      if (hasDuplicate)
        toRemove.push_back(i);
      else
        mol.setAtomPosition3d(i, wrappedCart); // wrap to 0.0
    }
    // Remove in reverse order so indices remain valid
    for (auto it = toRemove.rbegin(); it != toRemove.rend(); ++it)
      mol.removeAtom(*it);
  }
}

void SpaceGroups::fillTranslationalCopies(Molecule& mol, double cartTol)
{
  if (!mol.unitCell())
    return;
  UnitCell* uc = mol.unitCell();

  Array<unsigned char> atomicNumbers = mol.atomicNumbers();
  Array<Vector3> positions = mol.atomPositions3d();
  Index numAtoms = mol.atomCount();
  for (Index i = 0; i < numAtoms; ++i) {
    unsigned char atomicNum = atomicNumbers[i];
    Vector3 pos = uc->toFractional(positions[i]);

    Array<Vector3> newAtoms;
    // We need to check each coordinate to see if it is 0.0 or 1.0
    // .. if so, we need to generate the symmetric copy
    for (Index j = 0; j < 3; ++j) {
      Vector3 newPos = pos;
      if (fabs(pos[j]) < 0.001) {
        newPos[j] = 1.0;
        newAtoms.push_back(newPos);
      }
      if (fabs(pos[j] - 1.0) < 0.001) {
        newPos[j] = 0.0;
        newAtoms.push_back(newPos);
      }

      for (Index k = j + 1; k < 3; ++k) {
        if (fabs(pos[k]) < 0.001) {
          newPos[k] = 1.0;
          newAtoms.push_back(newPos);
          newPos[k] = 0.0; // revert for the other coords
        }
        if (fabs(pos[k] - 1.0) < 0.001) {
          newPos[k] = 0.0;
          newAtoms.push_back(newPos);
          newPos[k] = 1.0; // revert
        }
      }
    }
    // finally, check if all coordinates are 0.0
    if (fabs(pos[0]) < 0.001 && fabs(pos[1]) < 0.001 && fabs(pos[2]) < 0.001)
      newAtoms.push_back(Vector3(1.0, 1.0, 1.0));
    // or 1.0 .. unlikely, but possible
    if (fabs(pos[0] - 1.0) < 0.001 && fabs(pos[1] - 1.0) < 0.001 &&
        fabs(pos[2] - 1.0) < 0.001)
      newAtoms.push_back(Vector3(0.0, 0.0, 0.0));

    for (const auto& atomMat : newAtoms) {
      // The new atoms are in fractional coordinates. Convert to cartesian.
      Vector3 newCandidate = uc->toCartesian(atomMat);

      // If there is already an atom in this location within a
      // certain tolerance, do not add the atom.
      bool atomAlreadyPresent = false;
      Real cartTolSq = cartTol * cartTol;
      for (Index k = 0; k < mol.atomCount(); k++) {
        Real distSq = (mol.atomPosition3d(k) - newCandidate).squaredNorm();

        if (distSq <= cartTolSq) {
          atomAlreadyPresent = true;
          break;
        }
      }

      // If there is already an atom present here, just continue
      if (atomAlreadyPresent)
        continue;

      // If we got this far, add the atom!
      Atom newAtom = mol.addAtom(atomicNum);
      newAtom.setPosition3d(newCandidate);
    }
  }
}

void SpaceGroups::reduceToAsymmetricUnit(Molecule& mol,
                                         unsigned short hallNumber,
                                         double cartTol)
{
  if (!mol.unitCell())
    return;
  UnitCell* uc = mol.unitCell();

  // The number of atoms may change as we remove atoms, so don't cache
  // the number of atoms, atomic positions, or atomic numbers
  // There's no point in looking at the last atom
  for (Index i = 0; i + 1 < mol.atomCount(); ++i) {
    unsigned char atomicNum = mol.atomicNumber(i);
    Vector3 pos = uc->toFractional(mol.atomPosition3d(i));
    Array<Vector3> transformAtoms = getTransforms(hallNumber, pos);

    // Loop through the rest of the atoms in this crystal and see if any match
    // up with a transform
    for (Index j = i + 1; j < mol.atomCount(); ++j) {
      // If the atomic number does not match, skip over it
      if (mol.atomicNumber(j) != atomicNum)
        continue;

      Vector3 trialPos = mol.atomPosition3d(j);
      // Loop through the transform atoms
      // We skip 0 because it is the original atom.
      for (Index k = 1; k < transformAtoms.size(); ++k) {
        // The transform atoms are in fractional coordinates. Convert to
        // cartesian.
        Vector3 transformPos = uc->toCartesian(transformAtoms[k]);
        Real distance = uc->distance(trialPos, transformPos);
        // Is the atom within the cartesian tolerance distance?
        if (distance <= cartTol) {
          // Remove this atom and adjust the index
          mol.removeAtom(j);
          --j;
          break;
        }
      }
    }
  }
}

Array<Index> SpaceGroups::translationalUniqueAtoms(const Molecule& mol,
                                                   double tolerance)
{
  Array<Index> uniqueIndices;

  if (!mol.unitCell())
    return uniqueIndices;

  const UnitCell* uc = mol.unitCell();
  Index numAtoms = mol.atomCount();

  // Store wrapped coordinates for atoms we've already accepted
  std::vector<std::pair<unsigned char, Vector3>> accepted;

  for (Index i = 0; i < numAtoms; ++i) {
    unsigned char atomicNum = mol.atomicNumber(i);
    Vector3 fracCoords = uc->toFractional(mol.atomPosition3d(i));

    // Wrap coordinates to [0, 1) range for comparison
    Vector3 wrappedCoords;
    for (int c = 0; c < 3; ++c) {
      double coord = fracCoords[c];
      coord = coord - floor(coord);
      if (coord > 1.0 - tolerance)
        coord = 0.0;
      wrappedCoords[c] = coord;
    }

    // Check if this is a duplicate of a previously accepted atom
    bool isDuplicate = false;
    for (const auto& prev : accepted) {
      if (prev.first != atomicNum)
        continue;

      // Check if positions match within tolerance
      if ((wrappedCoords - prev.second).norm() < tolerance) {
        isDuplicate = true;
        break;
      }
    }

    if (!isDuplicate) {
      uniqueIndices.push_back(i);
      accepted.emplace_back(atomicNum, wrappedCoords);
    }
  }

  return uniqueIndices;
}

const char* SpaceGroups::transformsString(unsigned short hallNumber)
{
  if (hallNumber <= 530)
    return space_group_transforms[hallNumber];
  else
    return "";
}

} // namespace Avogadro::Core
