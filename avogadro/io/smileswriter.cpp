/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smileswriter.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>

#include <array>
#include <charconv>
#include <string>
#include <utility>
#include <vector>

namespace Avogadro::Io {

using Core::Elements;
using Core::Molecule;

namespace {

/** SMILES can express ring bond numbers 0-9 bare and 10-99 as %nn. */
const int MaxRingNumber = 99;

/** A bond that is not part of the depth-first spanning tree. */
struct RingClosure
{
  Index open;      //!< Atom the closure opens at (visited first).
  Index close;     //!< Atom it closes at.
  Index bond;      //!< The molecule bond it stands for.
  int number;      //!< The ring bond number assigned to it.
  Index nextOpen;  //!< Next closure opening at the same atom.
  Index nextClose; //!< Next closure closing at the same atom.
};

/** An edge of the spanning tree, from the perspective of the parent. */
struct Child
{
  Index atom;
  Index bond;
  Index next; //!< Next child of the same parent, in discovery order.
};

void appendUnsigned(std::string& out, unsigned long long value)
{
  char buffer[24];
  const std::to_chars_result result =
    std::to_chars(buffer, buffer + sizeof(buffer), value);
  out.append(buffer, result.ptr);
}

/**
 * Turns a molecule into a SMILES string.
 *
 * Both the traversal and the emission use an explicit stack rather than
 * recursion: a long chain -- a protein backbone, a polymer -- would otherwise
 * recurse once per atom and overflow the stack on platforms with a small
 * default, and this code must not crash on a valid molecule.
 *
 * For the same reason the per-atom collections are flat arrays with intrusive
 * next links rather than vectors of vectors, which would be one allocation per
 * atom on a structure that may hold hundreds of thousands of them.
 */
class Serializer
{
public:
  Serializer(const Molecule& mol, bool atomMaps)
    : m_mol(mol), m_atomMaps(atomMaps)
  {
    m_ringNumberUsed.fill(false);
  }

  bool run(std::string& smiles, std::string& error);

private:
  struct TraversalFrame
  {
    Index atom;
    Index next; //!< Cursor into this atom's slice of m_adjacency.
  };

  struct EmitFrame
  {
    Index atom;
    Index child; //!< Index into m_children, or MaxIndex when exhausted.
    bool closeParen;
  };

  void buildAdjacency();
  void traverse();
  void linkClosures();
  bool emit(std::string& smiles, std::string& error);
  bool emitAtom(std::string& out, Index atom, std::string& error);
  bool takeRingNumber(int& number, std::string& error);
  const char* bondSymbol(Index bond) const;
  void appendRingNumber(std::string& out, int number) const;

  const Molecule& m_mol;
  bool m_atomMaps;

  // Bonds incident to each atom, as a flat array indexed by m_adjacencyStart.
  std::vector<Index> m_adjacencyStart;
  std::vector<Index> m_adjacency;

  std::vector<Index> m_roots;
  std::vector<Child> m_children;
  std::vector<Index> m_firstChild;

  std::vector<RingClosure> m_closures;
  std::vector<Index> m_firstOpen;
  std::vector<Index> m_firstClose;

  std::array<bool, MaxRingNumber + 1> m_ringNumberUsed;
};

bool Serializer::run(std::string& smiles, std::string& error)
{
  buildAdjacency();
  traverse();
  linkClosures();
  return emit(smiles, error);
}

void Serializer::buildAdjacency()
{
  const Index atomCount = m_mol.atomCount();
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();

  m_adjacencyStart.assign(atomCount + 1, 0);
  for (const std::pair<Index, Index>& ends : pairs) {
    ++m_adjacencyStart[ends.first + 1];
    ++m_adjacencyStart[ends.second + 1];
  }
  for (Index atom = 0; atom < atomCount; ++atom)
    m_adjacencyStart[atom + 1] += m_adjacencyStart[atom];

  // Filling in bond order per atom reproduces the order Graph::edges() would
  // have given, so the traversal -- and the output -- is unchanged.
  m_adjacency.resize(2 * pairs.size());
  std::vector<Index> cursor(m_adjacencyStart.begin(),
                            m_adjacencyStart.end() - 1);
  for (Index bond = 0; bond < pairs.size(); ++bond) {
    m_adjacency[cursor[pairs[bond].first]++] = bond;
    m_adjacency[cursor[pairs[bond].second]++] = bond;
  }
}

void Serializer::traverse()
{
  const Index atomCount = m_mol.atomCount();
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();

  std::vector<bool> visited(atomCount, false);
  std::vector<bool> bondUsed(m_mol.bondCount(), false);
  std::vector<Index> lastChild(atomCount, MaxIndex);
  m_firstChild.assign(atomCount, MaxIndex);
  m_children.reserve(atomCount);

  std::vector<TraversalFrame> stack;

  for (Index root = 0; root < atomCount; ++root) {
    if (visited[root])
      continue;

    m_roots.push_back(root);
    visited[root] = true;
    stack.push_back(TraversalFrame{ root, m_adjacencyStart[root] });

    while (!stack.empty()) {
      TraversalFrame& frame = stack.back();
      const Index current = frame.atom;
      if (frame.next >= m_adjacencyStart[current + 1]) {
        stack.pop_back();
        continue;
      }

      const Index bond = m_adjacency[frame.next++];
      if (bondUsed[bond])
        continue;

      const std::pair<Index, Index>& ends = pairs[bond];
      const Index other = (ends.first == current) ? ends.second : ends.first;
      if (other == current)
        continue; // Defensive: a self bond has no SMILES representation.

      bondUsed[bond] = true;

      if (visited[other]) {
        // A non-tree edge in an undirected depth-first search always joins an
        // atom to one of its own ancestors -- a descendant would have marked
        // this bond used on its way down -- so the closure opens at the
        // ancestor, which is the atom already visited.
        m_closures.push_back(
          RingClosure{ other, current, bond, 0, MaxIndex, MaxIndex });
      } else {
        visited[other] = true;
        const Index entry = m_children.size();
        m_children.push_back(Child{ other, bond, MaxIndex });
        if (m_firstChild[current] == MaxIndex)
          m_firstChild[current] = entry;
        else
          m_children[lastChild[current]].next = entry;
        lastChild[current] = entry;
        // Invalidates frame, so nothing above may be used after this point.
        stack.push_back(TraversalFrame{ other, m_adjacencyStart[other] });
      }
    }
  }
}

void Serializer::linkClosures()
{
  const Index atomCount = m_mol.atomCount();
  m_firstOpen.assign(atomCount, MaxIndex);
  m_firstClose.assign(atomCount, MaxIndex);

  // Walking backwards means the head insertions leave each atom's list in
  // ascending closure order.
  for (Index i = m_closures.size(); i > 0; --i) {
    RingClosure& closure = m_closures[i - 1];
    closure.nextOpen = m_firstOpen[closure.open];
    m_firstOpen[closure.open] = i - 1;
    closure.nextClose = m_firstClose[closure.close];
    m_firstClose[closure.close] = i - 1;
  }
}

bool Serializer::takeRingNumber(int& number, std::string& error)
{
  for (int candidate = 1; candidate <= MaxRingNumber; ++candidate) {
    if (!m_ringNumberUsed[candidate]) {
      m_ringNumberUsed[candidate] = true;
      number = candidate;
      return true;
    }
  }

  error = "Too many ring closures are open at once; SMILES cannot express "
          "more than 99.";
  return false;
}

const char* Serializer::bondSymbol(Index bond) const
{
  switch (m_mol.bondOrders()[bond]) {
    case 2:
      return "=";
    case 3:
      return "#";
    case 4:
      return "$";
    default:
      // Order 1, and anything unset, is the SMILES default and written bare.
      return "";
  }
}

void Serializer::appendRingNumber(std::string& out, int number) const
{
  if (number < 10) {
    out += static_cast<char>('0' + number);
    return;
  }
  out += '%';
  out += static_cast<char>('0' + number / 10);
  out += static_cast<char>('0' + number % 10);
}

bool Serializer::emitAtom(std::string& out, Index atom, std::string& error)
{
  const unsigned char atomicNumber = m_mol.atomicNumbers()[atom];
  const int charge = m_mol.formalCharge(atom);
  const unsigned short isotope = m_mol.isotope(atom);

  out += '[';

  if (isotope != 0)
    appendUnsigned(out, isotope);

  // Anything without a real element symbol -- a dummy atom, a custom element,
  // or InvalidElement from an unrecognized input symbol -- becomes the SMILES
  // wildcard. Elements::symbol() would answer "Xx" for these, which is not
  // valid SMILES, and dropping the atom instead would break the atom mapping.
  if (atomicNumber > 0 && atomicNumber < Core::element_count)
    out += Elements::symbol(atomicNumber);
  else
    out += '*';

  if (charge != 0) {
    out += (charge > 0) ? '+' : '-';
    const int magnitude = (charge > 0) ? charge : -charge;
    if (magnitude > 1)
      appendUnsigned(out, magnitude);
  }

  if (m_atomMaps) {
    out += ':';
    appendUnsigned(out, atom + 1);
  }

  out += ']';

  // Ring bond numbers belong to the atom, ahead of any branch it opens.
  // Numbers are taken before they are released, so one freed here cannot be
  // reused on the same atom: "C11" would pair the two digits with each other
  // rather than with their intended partners.
  for (Index c = m_firstOpen[atom]; c != MaxIndex; c = m_closures[c].nextOpen) {
    if (!takeRingNumber(m_closures[c].number, error))
      return false;
    // Daylight allows the bond symbol on either or both occurrences, provided
    // they agree; writing it only where the closure opens keeps them trivially
    // consistent.
    out += bondSymbol(m_closures[c].bond);
    appendRingNumber(out, m_closures[c].number);
  }

  for (Index c = m_firstClose[atom]; c != MaxIndex;
       c = m_closures[c].nextClose) {
    appendRingNumber(out, m_closures[c].number);
    m_ringNumberUsed[m_closures[c].number] = false;
  }

  return true;
}

bool Serializer::emit(std::string& smiles, std::string& error)
{
  // Roughly a bracket atom plus a map class each, and a few characters per
  // ring closure; growth from here is rare.
  smiles.reserve(m_mol.atomCount() * 10 + m_closures.size() * 4 + 8);

  std::vector<EmitFrame> stack;

  for (Index component = 0; component < m_roots.size(); ++component) {
    if (component != 0)
      smiles += '.';

    const Index root = m_roots[component];
    if (!emitAtom(smiles, root, error))
      return false;
    stack.push_back(EmitFrame{ root, m_firstChild[root], false });

    while (!stack.empty()) {
      EmitFrame& frame = stack.back();
      if (frame.child == MaxIndex) {
        const bool closeParen = frame.closeParen;
        stack.pop_back();
        if (closeParen)
          smiles += ')';
        continue;
      }

      const Child child = m_children[frame.child];
      frame.child = child.next;

      // Every child but the last is a branch; the last one continues the
      // chain, which is what keeps the output free of redundant parentheses.
      const bool branch = (child.next != MaxIndex);
      if (branch)
        smiles += '(';
      smiles += bondSymbol(child.bond);
      if (!emitAtom(smiles, child.atom, error))
        return false;
      // Invalidates frame, so nothing above may be used after this point.
      stack.push_back(
        EmitFrame{ child.atom, m_firstChild[child.atom], branch });
    }
  }

  return true;
}

} // namespace

SmilesWriter::HydrogenMode SmilesWriter::effectiveHydrogenMode() const
{
  // Atom maps only exist inside brackets, and a hydrogen folded into a bracket
  // count has nowhere to carry one. Since Avogadro's hydrogens are real atoms
  // with real indices, folding them would produce a partial mapping.
  return m_atomMaps ? HydrogenMode::Explicit : m_hydrogenMode;
}

bool SmilesWriter::write(const Core::Molecule& molecule, std::string& smiles)
{
  smiles.clear();
  m_error.clear();

  if (effectiveHydrogenMode() != HydrogenMode::Explicit) {
    m_error = "Only explicit hydrogen output is implemented so far. Call "
              "setHydrogenMode(HydrogenMode::Explicit) or setAtomMaps(true).";
    return false;
  }

  if (molecule.atomCount() == 0)
    return true;

  Serializer serializer(molecule, m_atomMaps);
  if (!serializer.run(smiles, m_error)) {
    smiles.clear();
    return false;
  }

  return true;
}

} // namespace Avogadro::Io
