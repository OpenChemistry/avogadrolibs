/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smileswriter.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

#include <set>
#include <sstream>
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
  Index open = MaxIndex;  //!< Atom the closure opens at (visited first).
  Index close = MaxIndex; //!< Atom it closes at.
  Index bond = MaxIndex;  //!< The molecule bond it stands for.
  int number = 0;         //!< The ring bond number assigned to it.
};

/** An edge of the spanning tree, from the perspective of the parent. */
struct Child
{
  Index atom = MaxIndex;
  Index bond = MaxIndex;
};

/**
 * Turns a molecule into a SMILES string.
 *
 * Both the traversal and the emission use an explicit stack rather than
 * recursion: a long chain -- a protein backbone, a polymer -- would otherwise
 * recurse once per atom and overflow the stack on platforms with a small
 * default, and this code must not crash on a valid molecule.
 */
class Serializer
{
public:
  Serializer(const Molecule& mol, bool atomMaps)
    : m_mol(mol), m_atomMaps(atomMaps)
  {
  }

  bool run(std::string& smiles, std::string& error);

private:
  struct TraversalFrame
  {
    Index atom;
    size_t next;
    std::vector<size_t> incident;
  };

  struct EmitFrame
  {
    Index atom;
    size_t next;
    bool closeParen;
  };

  void traverse();
  bool numberClosures(std::string& error);
  void emit(std::string& smiles) const;
  void emitAtom(std::ostringstream& out, Index atom) const;
  std::string bondSymbol(Index bond) const;

  const Molecule& m_mol;
  bool m_atomMaps;

  std::vector<Index> m_roots;
  std::vector<Index> m_visitOrder;
  std::vector<std::vector<Child>> m_children;
  std::vector<RingClosure> m_closures;
  std::vector<std::vector<size_t>> m_atomClosures;
};

std::string ringNumber(int number)
{
  if (number < 10)
    return std::string(1, static_cast<char>('0' + number));

  std::string result("%");
  result += static_cast<char>('0' + number / 10);
  result += static_cast<char>('0' + number % 10);
  return result;
}

bool Serializer::run(std::string& smiles, std::string& error)
{
  traverse();
  if (!numberClosures(error))
    return false;
  emit(smiles);
  return true;
}

void Serializer::traverse()
{
  const Index atomCount = m_mol.atomCount();
  const Core::Graph& graph = m_mol.graph();
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();

  std::vector<bool> visited(atomCount, false);
  std::vector<bool> bondUsed(m_mol.bondCount(), false);
  m_visitOrder.assign(atomCount, MaxIndex);
  m_children.assign(atomCount, std::vector<Child>());

  Index order = 0;
  std::vector<TraversalFrame> stack;

  for (Index root = 0; root < atomCount; ++root) {
    if (visited[root])
      continue;

    m_roots.push_back(root);
    visited[root] = true;
    m_visitOrder[root] = order++;
    stack.push_back(TraversalFrame{ root, 0, graph.edges(root) });

    while (!stack.empty()) {
      TraversalFrame& frame = stack.back();
      if (frame.next >= frame.incident.size()) {
        stack.pop_back();
        continue;
      }

      const Index current = frame.atom;
      const Index bond = frame.incident[frame.next++];
      if (bondUsed[bond])
        continue;

      const std::pair<Index, Index>& ends = pairs[bond];
      const Index other = (ends.first == current) ? ends.second : ends.first;
      if (other == current)
        continue; // Defensive: a self bond has no SMILES representation.

      bondUsed[bond] = true;

      if (visited[other]) {
        // A non-tree edge in an undirected depth-first search always joins an
        // atom to one of its own ancestors, so the ancestor -- the one seen
        // first -- is where the closure opens.
        RingClosure closure;
        closure.bond = bond;
        if (m_visitOrder[other] < m_visitOrder[current]) {
          closure.open = other;
          closure.close = current;
        } else {
          closure.open = current;
          closure.close = other;
        }
        m_closures.push_back(closure);
      } else {
        visited[other] = true;
        m_visitOrder[other] = order++;
        m_children[current].push_back(Child{ other, bond });
        // Invalidates frame, so nothing above may be used after this point.
        stack.push_back(TraversalFrame{ other, 0, graph.edges(other) });
      }
    }
  }
}

bool Serializer::numberClosures(std::string& error)
{
  const Index atomCount = m_mol.atomCount();

  std::vector<std::vector<size_t>> opensAt(atomCount);
  std::vector<std::vector<size_t>> closesAt(atomCount);
  for (size_t i = 0; i < m_closures.size(); ++i) {
    opensAt[m_closures[i].open].push_back(i);
    closesAt[m_closures[i].close].push_back(i);
  }

  std::vector<Index> orderToAtom(atomCount, MaxIndex);
  for (Index atom = 0; atom < atomCount; ++atom)
    orderToAtom[m_visitOrder[atom]] = atom;

  m_atomClosures.assign(atomCount, std::vector<size_t>());
  std::set<int> freeNumbers;
  int nextNumber = 1;

  for (Index position = 0; position < atomCount; ++position) {
    const Index atom = orderToAtom[position];

    // Allocate before releasing, so a number freed here cannot be reused on
    // the same atom: "C11" would pair the two digits with each other rather
    // than with their intended partners.
    for (size_t closure : opensAt[atom]) {
      int number = 0;
      if (!freeNumbers.empty()) {
        number = *freeNumbers.begin();
        freeNumbers.erase(freeNumbers.begin());
      } else if (nextNumber <= MaxRingNumber) {
        number = nextNumber++;
      } else {
        error = "Too many ring closures are open at once; SMILES cannot "
                "express more than 99.";
        return false;
      }
      m_closures[closure].number = number;
      m_atomClosures[atom].push_back(closure);
    }

    for (size_t closure : closesAt[atom]) {
      freeNumbers.insert(m_closures[closure].number);
      m_atomClosures[atom].push_back(closure);
    }
  }

  return true;
}

std::string Serializer::bondSymbol(Index bond) const
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

void Serializer::emitAtom(std::ostringstream& out, Index atom) const
{
  const unsigned char atomicNumber = m_mol.atomicNumbers()[atom];
  const int charge = m_mol.formalCharge(atom);
  const unsigned short isotope = m_mol.isotope(atom);

  out << '[';

  if (isotope != 0)
    out << isotope;

  // Anything without a real element symbol -- a dummy atom, a custom element,
  // or InvalidElement from an unrecognized input symbol -- becomes the SMILES
  // wildcard. Elements::symbol() would answer "Xx" for these, which is not
  // valid SMILES, and dropping the atom instead would break the atom mapping.
  if (atomicNumber > 0 && atomicNumber < Core::element_count)
    out << Elements::symbol(atomicNumber);
  else
    out << '*';

  if (charge != 0) {
    out << (charge > 0 ? '+' : '-');
    const int magnitude = (charge > 0) ? charge : -charge;
    if (magnitude > 1)
      out << magnitude;
  }

  if (m_atomMaps)
    out << ':' << (atom + 1);

  out << ']';

  // Ring bond numbers belong to the atom, ahead of any branch it opens.
  for (size_t closure : m_atomClosures[atom]) {
    // Daylight allows the bond symbol on either or both occurrences, provided
    // they agree; writing it only where the closure opens keeps them trivially
    // consistent.
    if (m_closures[closure].open == atom)
      out << bondSymbol(m_closures[closure].bond);
    out << ringNumber(m_closures[closure].number);
  }
}

void Serializer::emit(std::string& smiles) const
{
  std::ostringstream out;
  std::vector<EmitFrame> stack;

  for (size_t component = 0; component < m_roots.size(); ++component) {
    if (component != 0)
      out << '.';

    emitAtom(out, m_roots[component]);
    stack.push_back(EmitFrame{ m_roots[component], 0, false });

    while (!stack.empty()) {
      const Index atom = stack.back().atom;
      const size_t childCount = m_children[atom].size();

      if (stack.back().next >= childCount) {
        const bool closeParen = stack.back().closeParen;
        stack.pop_back();
        if (closeParen)
          out << ')';
        continue;
      }

      const size_t which = stack.back().next++;
      const Child child = m_children[atom][which];

      // Every child but the last is a branch; the last one continues the
      // chain, which is what keeps the output free of redundant parentheses.
      const bool branch = (which + 1 < childCount);
      if (branch)
        out << '(';
      out << bondSymbol(child.bond);
      emitAtom(out, child.atom);
      stack.push_back(EmitFrame{ child.atom, 0, branch });
    }
  }

  smiles = out.str();
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
