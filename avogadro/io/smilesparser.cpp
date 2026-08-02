/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smilesparser.h"

#include "smilesvalence_p.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/utilities.h>

#include <string>
#include <vector>

namespace Avogadro::Io {

using Core::Elements;
using Core::Molecule;

namespace {

/** SMILES can express ring bond numbers 0-9 bare and 10-99 as %nn. */
const int MaxRingNumber = 99;

bool isAsciiDigit(char c)
{
  return c >= '0' && c <= '9';
}

bool isAsciiUpper(char c)
{
  return c >= 'A' && c <= 'Z';
}

bool isAsciiLower(char c)
{
  return c >= 'a' && c <= 'z';
}

char toAsciiUpper(char c)
{
  return isAsciiLower(c) ? static_cast<char>(c - 'a' + 'A') : c;
}

/** The five multi-letter chirality classes OpenSMILES defines. Anything else
 *  after a lone '@' is not part of the chirality symbol at all. */
bool isChiralClassCode(char a, char b)
{
  static const char* const codes[] = { "TH", "AL", "SP", "TB", "OH" };
  for (const char* code : codes) {
    if (a == code[0] && b == code[1])
      return true;
  }
  return false;
}

/** One written atom, before hydrogens are materialized. */
struct ParsedAtom
{
  unsigned char atomicNumber = 0;
  signed char charge = 0;
  unsigned short isotope = 0;
  size_t mapClass = 0;
  bool bracket = false;          //!< [...], where a hydrogen count is explicit.
  bool aromatic = false;         //!< Written lower case.
  unsigned char explicitH = 0;   //!< Bracket hydrogen count; unused otherwise.
  unsigned int bondOrderSum = 0; //!< Sum of orders of the bonds written to it.
};

/** One written bond, whether from the chain or a ring closure. */
struct ParsedBond
{
  Index a;
  Index b;
  unsigned char order;
};

/** A bond symbol read from the input, waiting to attach to what follows it. */
struct PendingBond
{
  bool set = false;
  unsigned char order = 1; //!< Meaningless when aromatic is true.
  bool aromatic = false;
  bool directional = false; //!< '/' or '\', discarded but tracked for a
                            //!< warning.
  size_t position = 0;
};

/** One ring bond number, 0-99, while it is open (or just after it closes). */
struct RingSlot
{
  bool open = false;
  Index atom = 0;
  int order = -1; //!< -1 means unspecified.
  bool aromatic = false;
  size_t openPosition = 0;
};

/**
 * Turns a SMILES string into local plain structs describing a molecule, then
 * -- only once the whole string has parsed without error -- builds the real
 * Core::Molecule from them. Building at the end, rather than as the string is
 * read, is what lets a failure partway through leave the caller's molecule
 * untouched at no extra cost.
 *
 * There is no recursion anywhere here, matching SmilesWriter: a branch stack
 * takes the place of one recursive call per '(', so a long, deeply nested
 * string cannot overflow the stack.
 */
class Parser
{
public:
  explicit Parser(const std::string& smiles) : m_input(smiles) {}

  bool run(Molecule& molecule, std::string& error, size_t& errorPosition,
           std::vector<std::string>& warnings, std::vector<size_t>& atomMaps);

private:
  bool parseStructure();
  bool parseBracketAtom(size_t bracketStart);
  bool parseBareAtom();
  bool consumeRingClosure();
  bool readDigits(size_t& i, unsigned long maxValue, unsigned long& value);

  void finishAtom(Index atom, size_t atomStart);
  void addRealBond(Index a, Index b, unsigned char order);
  bool bondExists(Index a, Index b) const;
  void noteAromatic(size_t position);

  void fail(const std::string& message, size_t position);

  void buildMolecule(Molecule& molecule, std::vector<size_t>& atomMaps) const;

  const std::string& m_input;
  size_t m_pos = 0;

  std::vector<ParsedAtom> m_atoms;
  std::vector<ParsedBond> m_bonds;

  // previousAtom, position of the '(' -- for "never closed" and "opened with
  // no preceding atom" diagnostics.
  std::vector<std::pair<Index, size_t>> m_branchStack;
  Index m_previousAtom = MaxIndex;
  PendingBond m_pendingBond;

  RingSlot m_ringSlots[MaxRingNumber + 1];

  bool m_sawAromatic = false;
  size_t m_aromaticPosition = 0;
  bool m_sawStereo = false;

  std::string m_error;
  size_t m_errorPosition = 0;
};

void Parser::fail(const std::string& message, size_t position)
{
  // The caller returns false immediately after calling this, so the first
  // failure is always the one that sticks.
  m_error = message;
  m_errorPosition = position;
}

void Parser::noteAromatic(size_t position)
{
  if (!m_sawAromatic) {
    m_sawAromatic = true;
    m_aromaticPosition = position;
  }
}

bool Parser::bondExists(Index a, Index b) const
{
  for (const ParsedBond& bond : m_bonds) {
    if ((bond.a == a && bond.b == b) || (bond.a == b && bond.b == a))
      return true;
  }
  return false;
}

void Parser::addRealBond(Index a, Index b, unsigned char order)
{
  m_bonds.push_back(ParsedBond{ a, b, order });
  m_atoms[a].bondOrderSum += order;
  m_atoms[b].bondOrderSum += order;
}

/**
 * Read a run of digits at @a i into @a value, advancing @a i past it.
 *
 * Returns false both for "no digits here" and for "the number is larger than
 * @a maxValue". Every caller checks for a digit before calling, so a false
 * return always means overflow -- keep that check when adding one.
 */
bool Parser::readDigits(size_t& i, unsigned long maxValue, unsigned long& value)
{
  value = 0;
  bool any = false;
  while (i < m_input.size() && isAsciiDigit(m_input[i])) {
    any = true;
    const unsigned long digit = static_cast<unsigned long>(m_input[i] - '0');
    if (value > (maxValue - digit) / 10) {
      // Consume the rest of the run so the caller's position tracking still
      // lands past the offending number, then report the overflow.
      while (i < m_input.size() && isAsciiDigit(m_input[i]))
        ++i;
      return false;
    }
    value = value * 10 + digit;
    ++i;
  }
  return any;
}

void Parser::finishAtom(Index atom, size_t atomStart)
{
  if (m_atoms[atom].aromatic)
    noteAromatic(atomStart);

  if (m_previousAtom != MaxIndex) {
    // Nothing written between two atoms means a single bond, except between
    // two lower case atoms, where it means an aromatic one -- but both of
    // those already tripped noteAromatic() through their own symbols, so the
    // order recorded for such a bond is never reached.
    unsigned char order = 1;
    if (m_pendingBond.set) {
      order = m_pendingBond.order;
      if (m_pendingBond.aromatic)
        noteAromatic(m_pendingBond.position);
      if (m_pendingBond.directional)
        m_sawStereo = true;
    }
    addRealBond(m_previousAtom, atom, order);
  }

  m_previousAtom = atom;
  m_pendingBond = PendingBond{};
}

bool Parser::parseBareAtom()
{
  const size_t start = m_pos;
  const char c = m_input[start];
  unsigned char atomicNumber = 0;
  bool aromatic = false;
  bool wildcard = false;
  size_t consumed = 0;

  // Cl and Br have to be matched before the single letter forms C and B.
  if (c == '*') {
    wildcard = true;
    consumed = 1;
  } else if (c == 'C' && start + 1 < m_input.size() &&
             m_input[start + 1] == 'l') {
    atomicNumber = 17;
    consumed = 2;
  } else if (c == 'B' && start + 1 < m_input.size() &&
             m_input[start + 1] == 'r') {
    atomicNumber = 35;
    consumed = 2;
  } else {
    switch (c) {
      case 'B':
        atomicNumber = 5;
        consumed = 1;
        break;
      case 'C':
        atomicNumber = 6;
        consumed = 1;
        break;
      case 'N':
        atomicNumber = 7;
        consumed = 1;
        break;
      case 'O':
        atomicNumber = 8;
        consumed = 1;
        break;
      case 'P':
        atomicNumber = 15;
        consumed = 1;
        break;
      case 'S':
        atomicNumber = 16;
        consumed = 1;
        break;
      case 'F':
        atomicNumber = 9;
        consumed = 1;
        break;
      case 'I':
        atomicNumber = 53;
        consumed = 1;
        break;
      case 'b':
        atomicNumber = 5;
        aromatic = true;
        consumed = 1;
        break;
      case 'c':
        atomicNumber = 6;
        aromatic = true;
        consumed = 1;
        break;
      case 'n':
        atomicNumber = 7;
        aromatic = true;
        consumed = 1;
        break;
      case 'o':
        atomicNumber = 8;
        aromatic = true;
        consumed = 1;
        break;
      case 'p':
        atomicNumber = 15;
        aromatic = true;
        consumed = 1;
        break;
      case 's':
        atomicNumber = 16;
        aromatic = true;
        consumed = 1;
        break;
      default:
        fail("Unexpected character.", start);
        return false;
    }
  }

  m_pos += consumed;

  ParsedAtom atom;
  atom.atomicNumber = wildcard ? 0 : atomicNumber;
  atom.aromatic = aromatic;
  atom.bracket = false;
  m_atoms.push_back(atom);
  finishAtom(static_cast<Index>(m_atoms.size() - 1), start);
  return true;
}

bool Parser::parseBracketAtom(size_t bracketStart)
{
  size_t i = bracketStart + 1;
  const size_t n = m_input.size();

  if (i >= n) {
    fail("Unterminated bracket atom.", bracketStart);
    return false;
  }
  if (m_input[i] == ']') {
    fail("Empty bracket atom.", bracketStart);
    return false;
  }

  ParsedAtom atom;
  atom.bracket = true;

  // Isotope: one or more digits immediately after '['.
  if (isAsciiDigit(m_input[i])) {
    const size_t digitsStart = i;
    unsigned long value = 0;
    if (!readDigits(i, 65535UL, value)) {
      fail("Isotope number is too large.", digitsStart);
      return false;
    }
    atom.isotope = static_cast<unsigned short>(value);
  }

  if (i >= n) {
    fail("Unterminated bracket atom.", bracketStart);
    return false;
  }

  // Symbol: any element symbol, the lower case aromatic forms, '*', or 'H'.
  const size_t symbolStart = i;
  bool wildcard = false;
  unsigned char atomicNumber = InvalidElement;
  bool aromatic = false;

  if (m_input[i] == '*') {
    wildcard = true;
    ++i;
  } else if (isAsciiUpper(m_input[i])) {
    // Try the two letter form first -- the second letter of a real element
    // symbol is always lower case -- and fall back to one letter.
    unsigned char found = InvalidElement;
    size_t consumed = 0;
    if (i + 1 < n && isAsciiLower(m_input[i + 1])) {
      found = Elements::atomicNumberFromSymbol(m_input.substr(i, 2));
      if (found != InvalidElement)
        consumed = 2;
    }
    if (consumed == 0) {
      found = Elements::atomicNumberFromSymbol(m_input.substr(i, 1));
      if (found != InvalidElement)
        consumed = 1;
    }
    if (consumed == 0) {
      fail("Unknown element symbol in bracket atom.", symbolStart);
      return false;
    }
    atomicNumber = found;
    i += consumed;
  } else if (isAsciiLower(m_input[i])) {
    // The aromatic forms: two letter (se, as, si, te) tried before one
    // letter, exactly as the bare atom grammar does.
    unsigned char found = InvalidElement;
    size_t consumed = 0;
    if (i + 1 < n) {
      const std::string candidate = m_input.substr(i, 2);
      if (candidate == "se" || candidate == "as" || candidate == "si" ||
          candidate == "te") {
        std::string proper = candidate;
        proper[0] = toAsciiUpper(proper[0]);
        found = Elements::atomicNumberFromSymbol(proper);
        if (found != InvalidElement)
          consumed = 2;
      }
    }
    if (consumed == 0 &&
        (m_input[i] == 'b' || m_input[i] == 'c' || m_input[i] == 'n' ||
         m_input[i] == 'o' || m_input[i] == 'p' || m_input[i] == 's')) {
      const std::string proper(1, toAsciiUpper(m_input[i]));
      found = Elements::atomicNumberFromSymbol(proper);
      if (found != InvalidElement)
        consumed = 1;
    }
    if (consumed == 0) {
      fail("Unknown element symbol in bracket atom.", symbolStart);
      return false;
    }
    atomicNumber = found;
    aromatic = true;
    i += consumed;
  } else {
    fail("Expected an element symbol in bracket atom.", symbolStart);
    return false;
  }

  atom.atomicNumber = wildcard ? 0 : atomicNumber;
  atom.aromatic = aromatic;

  // Chirality: "@", "@@", or "@" plus one of the named classes plus one or
  // two digits. Parsed only to be discarded -- see the class comment.
  if (i < n && m_input[i] == '@') {
    m_sawStereo = true;
    ++i;
    if (i < n && m_input[i] == '@') {
      ++i;
    } else if (i + 1 < n && isChiralClassCode(m_input[i], m_input[i + 1])) {
      i += 2;
      size_t digits = 0;
      while (i < n && isAsciiDigit(m_input[i]) && digits < 2) {
        ++i;
        ++digits;
      }
    }
  }

  // Hydrogen count: never inferred inside a bracket, so no 'H' means zero.
  if (i < n && m_input[i] == 'H') {
    ++i;
    atom.explicitH = 1;
    if (i < n && isAsciiDigit(m_input[i])) {
      atom.explicitH = static_cast<unsigned char>(m_input[i] - '0');
      ++i;
    }
  }

  // Charge: a digit run ("+2"), or the sign repeated ("++").
  if (i < n && (m_input[i] == '+' || m_input[i] == '-')) {
    const char sign = m_input[i];
    const size_t chargeStart = i;
    ++i;
    unsigned long magnitude = 1;
    if (i < n && isAsciiDigit(m_input[i])) {
      if (!readDigits(i, 127UL, magnitude)) {
        fail("Formal charge is too large.", chargeStart);
        return false;
      }
    } else {
      while (i < n && m_input[i] == sign) {
        ++magnitude;
        ++i;
      }
      if (magnitude > 127) {
        fail("Formal charge is too large.", chargeStart);
        return false;
      }
    }
    atom.charge =
      static_cast<signed char>(sign == '+' ? static_cast<long>(magnitude)
                                           : -static_cast<long>(magnitude));
  }

  // Atom class: ':' followed by digits.
  if (i < n && m_input[i] == ':') {
    const size_t classStart = i;
    ++i;
    if (i >= n || !isAsciiDigit(m_input[i])) {
      fail("Expected digits after ':' for an atom class.", classStart);
      return false;
    }
    unsigned long value = 0;
    if (!readDigits(i, 999999999UL, value)) {
      fail("Atom class number is too large.", classStart);
      return false;
    }
    atom.mapClass = static_cast<size_t>(value);
  }

  if (i >= n) {
    fail("Unterminated bracket atom.", bracketStart);
    return false;
  }
  if (m_input[i] != ']') {
    fail("Unexpected character inside bracket atom.", i);
    return false;
  }
  ++i;

  m_pos = i;
  m_atoms.push_back(atom);
  finishAtom(static_cast<Index>(m_atoms.size() - 1), bracketStart);
  return true;
}

bool Parser::consumeRingClosure()
{
  const size_t start = m_pos;
  int number = 0;
  if (m_input[m_pos] == '%') {
    ++m_pos;
    if (m_pos + 1 >= m_input.size() || !isAsciiDigit(m_input[m_pos]) ||
        !isAsciiDigit(m_input[m_pos + 1])) {
      fail("'%' must be followed by exactly two digits.", start);
      return false;
    }
    number = (m_input[m_pos] - '0') * 10 + (m_input[m_pos + 1] - '0');
    m_pos += 2;
  } else {
    number = m_input[m_pos] - '0';
    ++m_pos;
  }

  if (m_previousAtom == MaxIndex) {
    fail("Ring closure with no preceding atom.", start);
    return false;
  }

  RingSlot& slot = m_ringSlots[number];
  if (!slot.open) {
    slot.open = true;
    slot.atom = m_previousAtom;
    slot.openPosition = start;
    if (m_pendingBond.set) {
      slot.order = m_pendingBond.order;
      slot.aromatic = m_pendingBond.aromatic;
      if (m_pendingBond.aromatic)
        noteAromatic(m_pendingBond.position);
      if (m_pendingBond.directional)
        m_sawStereo = true;
    } else {
      slot.order = -1;
      slot.aromatic = false;
    }
    m_pendingBond = PendingBond{};
    return true;
  }

  // Closing: pair this occurrence with the one that opened it.
  const Index openAtom = slot.atom;
  if (openAtom == m_previousAtom) {
    fail("A ring closure cannot bond an atom to itself.", start);
    return false;
  }

  int closeOrder = -1;
  bool closeAromatic = false;
  if (m_pendingBond.set) {
    closeOrder = m_pendingBond.order;
    closeAromatic = m_pendingBond.aromatic;
    if (m_pendingBond.aromatic)
      noteAromatic(m_pendingBond.position);
    if (m_pendingBond.directional)
      m_sawStereo = true;
  }

  const bool openSpecified = slot.order != -1 || slot.aromatic;
  const bool closeSpecified = closeOrder != -1 || closeAromatic;
  if (openSpecified && closeSpecified) {
    const bool disagree = (slot.aromatic != closeAromatic) ||
                          (!slot.aromatic && slot.order != closeOrder);
    if (disagree) {
      fail("The two ends of this ring closure specify different bonds.",
           m_pendingBond.set ? m_pendingBond.position : start);
      return false;
    }
  }

  // Aromatic bond orders are never used past the rejection in run(), so
  // recording them as plain single bonds here is harmless.
  unsigned char order = 1;
  if (openSpecified)
    order = slot.aromatic ? 1 : static_cast<unsigned char>(slot.order);
  else if (closeSpecified)
    order = closeAromatic ? 1 : static_cast<unsigned char>(closeOrder);
  else if (m_atoms[openAtom].aromatic && m_atoms[m_previousAtom].aromatic)
    order = 1; // Aromatic by default; already noted through the atoms.

  if (bondExists(openAtom, m_previousAtom)) {
    fail("This ring closure duplicates a bond that already exists between "
         "these two atoms.",
         start);
    return false;
  }

  addRealBond(openAtom, m_previousAtom, order);
  slot.open = false;
  m_pendingBond = PendingBond{};
  return true;
}

bool Parser::parseStructure()
{
  const size_t n = m_input.size();

  while (m_pos < n) {
    const char c = m_input[m_pos];

    if (c == '(') {
      if (m_pendingBond.set) {
        fail("A bond symbol must be followed by an atom or ring closure.",
             m_pendingBond.position);
        return false;
      }
      if (m_previousAtom == MaxIndex) {
        fail("'(' with no preceding atom to branch from.", m_pos);
        return false;
      }
      m_branchStack.emplace_back(m_previousAtom, m_pos);
      ++m_pos;
      continue;
    }

    if (c == ')') {
      if (m_pendingBond.set) {
        fail("A bond symbol must be followed by an atom or ring closure.",
             m_pendingBond.position);
        return false;
      }
      if (m_branchStack.empty()) {
        fail("')' has no matching '('.", m_pos);
        return false;
      }
      m_previousAtom = m_branchStack.back().first;
      m_branchStack.pop_back();
      ++m_pos;
      continue;
    }

    if (c == '.') {
      if (m_pendingBond.set) {
        fail("A bond symbol must be followed by an atom or ring closure.",
             m_pendingBond.position);
        return false;
      }
      m_previousAtom = MaxIndex;
      ++m_pos;
      continue;
    }

    if (c == '-' || c == '=' || c == '#' || c == '$' || c == ':' || c == '/' ||
        c == '\\') {
      if (m_pendingBond.set) {
        fail("Unexpected character.", m_pos);
        return false;
      }
      if (m_previousAtom == MaxIndex) {
        fail("Bond symbol with no preceding atom.", m_pos);
        return false;
      }
      PendingBond pending;
      pending.set = true;
      pending.position = m_pos;
      switch (c) {
        case '-':
          pending.order = 1;
          break;
        case '=':
          pending.order = 2;
          break;
        case '#':
          pending.order = 3;
          break;
        case '$':
          pending.order = 4;
          break;
        case ':':
          pending.aromatic = true;
          break;
        case '/':
        case '\\':
          pending.order = 1;
          pending.directional = true;
          break;
      }
      m_pendingBond = pending;
      ++m_pos;
      continue;
    }

    if (c == '[') {
      if (!parseBracketAtom(m_pos))
        return false;
      continue;
    }

    if (c == '%' || isAsciiDigit(c)) {
      if (!consumeRingClosure())
        return false;
      continue;
    }

    if (!parseBareAtom())
      return false;
  }

  if (m_pendingBond.set) {
    fail("A bond symbol must be followed by an atom or ring closure.",
         m_pendingBond.position);
    return false;
  }
  if (!m_branchStack.empty()) {
    fail("'(' was never closed.", m_branchStack.back().second);
    return false;
  }

  // Report whichever ring number was opened first if more than one is still
  // open, since that is the one whose problem the input hit first.
  bool anyOpen = false;
  size_t firstOpenPosition = 0;
  for (int number = 0; number <= MaxRingNumber; ++number) {
    if (m_ringSlots[number].open &&
        (!anyOpen || m_ringSlots[number].openPosition < firstOpenPosition)) {
      anyOpen = true;
      firstOpenPosition = m_ringSlots[number].openPosition;
    }
  }
  if (anyOpen) {
    fail("A ring closure was opened but never closed.", firstOpenPosition);
    return false;
  }

  return true;
}

void Parser::buildMolecule(Molecule& molecule,
                           std::vector<size_t>& atomMaps) const
{
  const Index writtenCount = static_cast<Index>(m_atoms.size());

  for (const ParsedAtom& atom : m_atoms) {
    const Molecule::AtomType added = molecule.addAtom(atom.atomicNumber);
    if (atom.charge != 0)
      molecule.setFormalCharge(added.index(), atom.charge);
    if (atom.isotope != 0)
      molecule.setIsotope(added.index(), atom.isotope);
  }

  for (const ParsedBond& bond : m_bonds)
    molecule.addBond(bond.a, bond.b, bond.order);

  // Second pass: every implied or bracket-counted hydrogen becomes a real
  // atom, appended after every written atom and grouped by the atom it
  // belongs to. This has to wait until now because a bare atom's implied
  // count depends on its bond order sum, which is not final until its ring
  // closures -- possibly written much later in the string -- have closed.
  for (Index parent = 0; parent < writtenCount; ++parent) {
    const ParsedAtom& atom = m_atoms[parent];
    int hCount = 0;
    if (atom.bracket) {
      hCount = atom.explicitH;
    } else if (atom.atomicNumber != 0) {
      // Bare, non-wildcard: every bare atom this parser accepts is in the
      // organic subset, so this always returns a real count.
      const int implied =
        smilesImpliedHydrogens(atom.atomicNumber, atom.bondOrderSum);
      hCount = (implied == SmilesNotOrganicSubset) ? 0 : implied;
    }
    // A bare wildcard has no implied hydrogen rule and gets none.

    for (int h = 0; h < hCount; ++h) {
      const Molecule::AtomType hydrogen = molecule.addAtom(1);
      molecule.addBond(parent, hydrogen.index(), 1);
    }
  }

  atomMaps.assign(molecule.atomCount(), 0);
  for (Index i = 0; i < writtenCount; ++i)
    atomMaps[i] = m_atoms[i].mapClass;
}

bool Parser::run(Molecule& molecule, std::string& error, size_t& errorPosition,
                 std::vector<std::string>& warnings,
                 std::vector<size_t>& atomMaps)
{
  if (!parseStructure()) {
    error = m_error;
    errorPosition = m_errorPosition;
    return false;
  }

  // ---------------------------------------------------------------------
  // Aromatic input is rejected here, as a single block, because turning an
  // aromatic ring back into alternating single and double bonds requires a
  // kekulizer that does not exist yet. Once one does, replace this block
  // with a call to it instead of failing.
  if (m_sawAromatic) {
    error = "Aromatic SMILES requires kekulization, which is not yet "
            "implemented.";
    errorPosition = m_aromaticPosition;
    return false;
  }
  // ---------------------------------------------------------------------

  if (m_sawStereo) {
    warnings.push_back(
      "Stereochemistry (chirality and bond direction markers) was "
      "discarded: a freshly parsed molecule has no coordinates for it to "
      "describe.");
  }

  buildMolecule(molecule, atomMaps);
  return true;
}

} // namespace

bool SmilesParser::parse(const std::string& smiles, Core::Molecule& molecule)
{
  // clearAtoms() rather than assigning a default Molecule: this takes a
  // reference to the base class, so assignment would slice a QtGui::Molecule
  // and leave its derived state behind. clearAtoms() is virtual and clears
  // everything indexed by atom, leaving only molecule-wide data such as the
  // name, which the title below overwrites when the string carries one.
  molecule.clearAtoms();
  m_error.clear();
  m_errorPosition = 0;
  m_warnings.clear();
  m_atomMaps.clear();

  // The string ends at the first space, tab, CR or LF; anything after that,
  // trimmed, is a title rather than part of the structure. This is the same
  // convention xyzformat's comment line uses for a molecule name.
  const size_t titleStart = smiles.find_first_of(" \t\r\n");
  const std::string structure =
    (titleStart == std::string::npos) ? smiles : smiles.substr(0, titleStart);
  const std::string title = (titleStart == std::string::npos)
                              ? std::string()
                              : Core::trimmed(smiles.substr(titleStart));

  Parser parser(structure);
  if (!parser.run(molecule, m_error, m_errorPosition, m_warnings, m_atomMaps)) {
    // run() builds nothing until the whole string has parsed, so there is
    // nothing to undo here; this only restates the guarantee.
    molecule.clearAtoms();
    m_atomMaps.clear();
    return false;
  }

  if (!title.empty())
    molecule.setData("name", title);

  return true;
}

} // namespace Avogadro::Io
