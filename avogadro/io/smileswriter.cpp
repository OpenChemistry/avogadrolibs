/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "smileswriter.h"

#include "atomequivalence_p.h"
#include "smilesvalence_p.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

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

/** Tetrahedral parity, in the sense SMILES writes it. */
enum class Chirality : char
{
  None,
  Anticlockwise, //!< "@"
  Clockwise      //!< "@@"
};

/**
 * Which way a directional single bond points, going from the first to the
 * second atom of Molecule::bondPairs(). Writing the bond in the other
 * direction reverses the symbol.
 */
enum class Direction : char
{
  None,
  Up,  //!< "/"
  Down //!< "\"
};

Direction opposite(Direction direction)
{
  return direction == Direction::Up ? Direction::Down : Direction::Up;
}

/**
 * A tetrahedron flatter than this is treated as having no usable handedness.
 * Real centres are far from the threshold -- four bonds of about 1.5 A give a
 * magnitude in the tens -- so this only catches degenerate input such as a
 * molecule whose coordinates were never set.
 */
const Real MinTetrahedronVolume = 1e-4;

/**
 * Below this a separation carries no usable direction. Applied to the double
 * bond axis, and to how far a substituent sits off that axis, so a collinear
 * or coincident arrangement is reported as having no cis/trans rather than
 * being assigned one from rounding noise.
 */
const Real MinBondLengthSquared = 1e-6;

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

/** Whether the element has a symbol that is meaningful in SMILES. */
bool hasElementSymbol(unsigned char atomicNumber)
{
  // Excludes 0, custom elements, and InvalidElement; Elements::symbol() would
  // answer "Xx" for those, which is not valid SMILES.
  return atomicNumber > 0 && atomicNumber < Core::element_count;
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
  Serializer(const Molecule& mol, SmilesWriter::HydrogenMode mode,
             bool atomMaps)
    : m_mol(mol), m_mode(mode), m_atomMaps(atomMaps)
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

  void suppressHydrogens();
  void buildAdjacency();
  void traverse();
  void linkClosures();
  void markRingBonds();
  void assignChirality();
  void assignBondStereo();
  bool writtenNeighbors(Index atom, Index neighbors[4]) const;
  bool directionalBond(Index carbon, Index partner, Index& bond,
                       Index& substituent) const;
  bool emit(std::string& smiles, std::string& error);
  bool emitAtom(std::string& out, Index atom, std::string& error);
  bool needsBrackets(Index atom) const;
  bool takeRingNumber(int& number, std::string& error);
  unsigned int writtenBondOrder(Index bond) const;
  const char* bondSymbol(Index bond, Index fromAtom) const;
  void appendRingNumber(std::string& out, int number) const;

  const Molecule& m_mol;
  SmilesWriter::HydrogenMode m_mode;
  bool m_atomMaps;

  // Hydrogens folded into a neighbour rather than written as their own atom.
  std::vector<bool> m_suppressed;
  std::vector<unsigned char> m_implicitH;
  std::vector<Index> m_suppressedHydrogen;
  std::vector<unsigned int> m_bondOrderSum;

  std::vector<Index> m_parent;
  std::vector<Index> m_parentBond;
  std::vector<Index> m_classes;
  std::vector<Chirality> m_chirality;
  std::vector<bool> m_bondInRing;
  std::vector<Direction> m_bondDirection;

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
  suppressHydrogens();
  buildAdjacency();
  traverse();
  linkClosures();
  markRingBonds();

  // Both kinds of stereochemistry are read out of the coordinates, and both
  // need to know which substituents are constitutionally distinguishable.
  m_chirality.assign(m_mol.atomCount(), Chirality::None);
  m_bondDirection.assign(m_mol.bondCount(), Direction::None);
  if (m_mol.atomPositions3d().size() == m_mol.atomCount()) {
    m_classes = atomEquivalenceClasses(m_mol);
    assignChirality();
    assignBondStereo();
  }

  return emit(smiles, error);
}

unsigned int Serializer::writtenBondOrder(Index bond) const
{
  // An unset order is written as a single bond, so it counts as one against
  // the valence model.
  const unsigned char order = m_mol.bondOrders()[bond];
  return (order < 1) ? 1u : order;
}

void Serializer::suppressHydrogens()
{
  const Index atomCount = m_mol.atomCount();
  m_suppressed.assign(atomCount, false);
  m_implicitH.assign(atomCount, 0);
  m_suppressedHydrogen.assign(atomCount, MaxIndex);

  // Explicit mode keeps every hydrogen as an atom of its own, which is also
  // what atom mapping requires -- a folded hydrogen has nowhere to carry a
  // map class.
  if (m_mode == SmilesWriter::HydrogenMode::Explicit)
    return;

  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();
  const Core::Array<unsigned char>& numbers = m_mol.atomicNumbers();

  std::vector<Index> degree(atomCount, 0);
  for (const std::pair<Index, Index>& ends : pairs) {
    ++degree[ends.first];
    ++degree[ends.second];
  }

  for (Index bond = 0; bond < pairs.size(); ++bond) {
    if (m_mol.bondOrders()[bond] > 1)
      continue;

    const std::pair<Index, Index>& ends = pairs[bond];
    for (int side = 0; side < 2; ++side) {
      const Index hydrogen = (side == 0) ? ends.first : ends.second;
      const Index neighbor = (side == 0) ? ends.second : ends.first;

      // A hydrogen bonded to another hydrogen keeps its atom, so H2 stays
      // "[H][H]" rather than collapsing into something meaningless. More than
      // one bond means a bridging hydrogen, as in diborane, which also has to
      // stay written. An isotope or a charge needs a bracket of its own, so
      // deuterium and hydride survive as atoms without any special case.
      //
      // A hydrogen on a chiral atom may be folded away: it keeps a defined
      // slot in the neighbour ordering, immediately after the atom the centre
      // was reached from, and writtenNeighbors() places it there.
      if (numbers[hydrogen] != 1 || numbers[neighbor] == 1)
        continue;
      if (degree[hydrogen] != 1)
        continue;
      if (m_mol.formalCharge(hydrogen) != 0 || m_mol.isotope(hydrogen) != 0)
        continue;

      m_suppressed[hydrogen] = true;
      m_suppressedHydrogen[neighbor] = hydrogen;
      ++m_implicitH[neighbor];
    }
  }
}

void Serializer::buildAdjacency()
{
  const Index atomCount = m_mol.atomCount();
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();

  m_adjacencyStart.assign(atomCount + 1, 0);
  m_bondOrderSum.assign(atomCount, 0);

  Index kept = 0;
  for (Index bond = 0; bond < pairs.size(); ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    if (m_suppressed[ends.first] || m_suppressed[ends.second])
      continue;
    ++m_adjacencyStart[ends.first + 1];
    ++m_adjacencyStart[ends.second + 1];
    m_bondOrderSum[ends.first] += writtenBondOrder(bond);
    m_bondOrderSum[ends.second] += writtenBondOrder(bond);
    ++kept;
  }
  for (Index atom = 0; atom < atomCount; ++atom)
    m_adjacencyStart[atom + 1] += m_adjacencyStart[atom];

  // Filling in bond order per atom reproduces the order Graph::edges() would
  // have given, so the traversal -- and the output -- is unchanged.
  m_adjacency.resize(2 * kept);
  std::vector<Index> cursor(m_adjacencyStart.begin(),
                            m_adjacencyStart.end() - 1);
  for (Index bond = 0; bond < pairs.size(); ++bond) {
    const std::pair<Index, Index>& ends = pairs[bond];
    if (m_suppressed[ends.first] || m_suppressed[ends.second])
      continue;
    m_adjacency[cursor[ends.first]++] = bond;
    m_adjacency[cursor[ends.second]++] = bond;
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
  m_parent.assign(atomCount, MaxIndex);
  m_parentBond.assign(atomCount, MaxIndex);
  m_children.reserve(atomCount);

  std::vector<TraversalFrame> stack;

  for (Index root = 0; root < atomCount; ++root) {
    if (visited[root] || m_suppressed[root])
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
        m_parent[other] = current;
        m_parentBond[other] = bond;
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

bool Serializer::writtenNeighbors(Index atom, Index neighbors[4]) const
{
  // The order SMILES assigns to a chiral atom's neighbours is the order they
  // appear in the string: the atom it was reached from, then a hydrogen folded
  // into the bracket, then the ring closure digits, then the branches. That is
  // exactly the order this writer emits them in.
  Index found = 0;
  const auto add = [&](Index neighbor) {
    if (found < 4)
      neighbors[found] = neighbor;
    ++found;
  };

  if (m_parent[atom] != MaxIndex)
    add(m_parent[atom]);

  // Two or more folded hydrogens are indistinguishable, so such an atom is
  // never a stereocentre and there is no need to order them.
  if (m_implicitH[atom] == 1)
    add(m_suppressedHydrogen[atom]);
  else if (m_implicitH[atom] > 1)
    return false;

  for (Index c = m_firstOpen[atom]; c != MaxIndex; c = m_closures[c].nextOpen)
    add(m_closures[c].close);
  for (Index c = m_firstClose[atom]; c != MaxIndex; c = m_closures[c].nextClose)
    add(m_closures[c].open);
  for (Index c = m_firstChild[atom]; c != MaxIndex; c = m_children[c].next)
    add(m_children[c].atom);

  return found == 4;
}

void Serializer::markRingBonds()
{
  m_bondInRing.assign(m_mol.bondCount(), false);

  // A ring closure and every tree bond between its two ends form one cycle.
  for (const RingClosure& closure : m_closures) {
    m_bondInRing[closure.bond] = true;
    Index atom = closure.close;
    while (atom != closure.open && atom != MaxIndex) {
      const Index bond = m_parentBond[atom];
      if (bond == MaxIndex)
        break;
      m_bondInRing[bond] = true;
      atom = m_parent[atom];
    }
  }
}

void Serializer::assignChirality()
{
  const Index atomCount = m_mol.atomCount();
  const Core::Array<Vector3>& positions = m_mol.atomPositions3d();
  const std::vector<Index>& classes = m_classes;

  Index neighbors[4];
  for (Index atom = 0; atom < atomCount; ++atom) {
    if (m_suppressed[atom] || !writtenNeighbors(atom, neighbors))
      continue;

    // Only a centre whose four substituents are all constitutionally
    // different is stereogenic. Without this test every methyl carbon would
    // pick up a meaningless "@".
    bool distinct = true;
    for (int i = 0; i < 4 && distinct; ++i)
      for (int j = i + 1; j < 4 && distinct; ++j)
        distinct = classes[neighbors[i]] != classes[neighbors[j]];
    if (!distinct)
      continue;

    // Viewed with the first neighbour between the viewer and the centre, are
    // the other three arranged anticlockwise? That is the sign of the volume
    // of the tetrahedron they span, taken from the first neighbour.
    const Vector3& first = positions[neighbors[0]];
    const Real volume = (positions[neighbors[1]] - first)
                          .dot((positions[neighbors[2]] - first)
                                 .cross(positions[neighbors[3]] - first));

    if (volume < -MinTetrahedronVolume)
      m_chirality[atom] = Chirality::Anticlockwise;
    else if (volume > MinTetrahedronVolume)
      m_chirality[atom] = Chirality::Clockwise;
  }
}

bool Serializer::directionalBond(Index carbon, Index partner, Index& bond,
                                 Index& substituent) const
{
  // A marker can only go on a bond that is actually written as a bond: not a
  // folded hydrogen, and not a ring bond, whose two halves would each need
  // their own consistent symbol.
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();
  bool found = false;

  for (Index candidate : m_mol.graph().edges(carbon)) {
    const std::pair<Index, Index>& ends = pairs[candidate];
    const Index other = (ends.first == carbon) ? ends.second : ends.first;
    if (other == partner)
      continue;
    if (m_suppressed[other] || m_bondInRing[candidate])
      continue;

    // Prefer the lowest bond index, so the choice does not depend on the
    // order the double bonds happen to be visited in.
    if (!found || candidate < bond) {
      bond = candidate;
      substituent = other;
      found = true;
    }
  }

  return found;
}

void Serializer::assignBondStereo()
{
  const Core::Array<std::pair<Index, Index>>& pairs = m_mol.bondPairs();
  const Core::Array<unsigned char>& orders = m_mol.bondOrders();
  const Core::Array<Vector3>& positions = m_mol.atomPositions3d();
  const Core::Graph& graph = m_mol.graph();

  for (Index bond = 0; bond < m_mol.bondCount(); ++bond) {
    if (orders[bond] != 2 || m_bondInRing[bond])
      continue;

    const Index first = pairs[bond].first;
    const Index second = pairs[bond].second;
    if (m_suppressed[first] || m_suppressed[second])
      continue;

    // Each end has to be a plain sp2 centre with something to orient. More
    // than one double bond means a cumulated system, whose stereochemistry is
    // axial rather than cis/trans.
    bool usable = true;
    Index substituents[2][2];
    Index substituentCount[2] = { 0, 0 };
    const Index carbons[2] = { first, second };
    for (int end = 0; end < 2 && usable; ++end) {
      Index doubleBonds = 0;
      for (Index incident : graph.edges(carbons[end])) {
        if (orders[incident] == 2)
          ++doubleBonds;
        if (incident == bond)
          continue;
        const std::pair<Index, Index>& ends = pairs[incident];
        const Index other =
          (ends.first == carbons[end]) ? ends.second : ends.first;
        if (substituentCount[end] < 2)
          substituents[end][substituentCount[end]] = other;
        ++substituentCount[end];
      }
      usable = (doubleBonds == 1) && substituentCount[end] >= 1 &&
               substituentCount[end] <= 2;
    }
    if (!usable)
      continue;

    // Two indistinguishable substituents at either end means there is no
    // cis/trans to describe -- 1,1-dichloroethene, or a terminal =CH2.
    bool stereogenic = true;
    for (int end = 0; end < 2; ++end) {
      if (substituentCount[end] == 2 &&
          m_classes[substituents[end][0]] == m_classes[substituents[end][1]])
        stereogenic = false;
    }
    if (!stereogenic)
      continue;

    Index markerBond[2];
    Index markerAtom[2];
    if (!directionalBond(first, second, markerBond[0], markerAtom[0]) ||
        !directionalBond(second, first, markerBond[1], markerAtom[1]))
      continue;

    // Are the two marked substituents on the same side of the double bond?
    // Only the component perpendicular to the bond axis carries that.
    const Vector3 axis = positions[second] - positions[first];
    const Real axisLengthSquared = axis.squaredNorm();
    if (axisLengthSquared < MinBondLengthSquared)
      continue;

    Vector3 offsets[2];
    bool flat = false;
    for (int end = 0; end < 2; ++end) {
      const Vector3 raw = positions[markerAtom[end]] - positions[carbons[end]];
      offsets[end] = raw - axis * (raw.dot(axis) / axisLengthSquared);
      if (offsets[end].squaredNorm() < MinBondLengthSquared)
        flat = true;
    }
    if (flat)
      continue; // Collinear substituent: nothing to be on a side of.

    const bool sameSide = offsets[0].dot(offsets[1]) > 0.0;

    // "Up" is arbitrary, so start by putting the first substituent up. A
    // marker written substituent-first points away from it, hence the flip.
    Direction sides[2] = { Direction::Up,
                           sameSide ? Direction::Up : Direction::Down };
    Direction wanted[2];
    for (int end = 0; end < 2; ++end) {
      const bool substituentFirst =
        pairs[markerBond[end]].first == markerAtom[end];
      wanted[end] = substituentFirst ? opposite(sides[end]) : sides[end];
    }

    // A single bond shared with an earlier double bond -- the middle bond of a
    // diene -- already carries a symbol, and that fixes which side is "up"
    // here. Flipping both markers describes the same geometry.
    for (int end = 0; end < 2; ++end) {
      if (m_bondDirection[markerBond[end]] != Direction::None &&
          m_bondDirection[markerBond[end]] != wanted[end]) {
        wanted[0] = opposite(wanted[0]);
        wanted[1] = opposite(wanted[1]);
        break;
      }
    }

    // If it still disagrees the constraints cannot all be met, which a ring of
    // conjugated double bonds can produce. Leave this one unspecified rather
    // than contradict a bond already written.
    bool consistent = true;
    for (int end = 0; end < 2; ++end) {
      if (m_bondDirection[markerBond[end]] != Direction::None &&
          m_bondDirection[markerBond[end]] != wanted[end])
        consistent = false;
    }
    if (!consistent)
      continue;

    m_bondDirection[markerBond[0]] = wanted[0];
    m_bondDirection[markerBond[1]] = wanted[1];
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

const char* Serializer::bondSymbol(Index bond, Index fromAtom) const
{
  switch (m_mol.bondOrders()[bond]) {
    case 2:
      return "=";
    case 3:
      return "#";
    case 4:
      return "$";
    default:
      break;
  }

  // A single bond next to a stereogenic double bond carries its direction,
  // which is stated relative to the stored atom order and so reverses when the
  // traversal writes the bond the other way round.
  if (m_bondDirection[bond] != Direction::None) {
    Direction direction = m_bondDirection[bond];
    if (m_mol.bondPairs()[bond].first != fromAtom)
      direction = opposite(direction);
    return direction == Direction::Up ? "/" : "\\";
  }

  // Order 1, and anything unset, is the SMILES default and written bare.
  return "";
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

bool Serializer::needsBrackets(Index atom) const
{
  // Bracket and Explicit both spell every atom out; only Implicit tries for a
  // bare form. Atom maps live inside brackets, and already force Explicit.
  if (m_mode != SmilesWriter::HydrogenMode::Implicit)
    return true;

  // Chirality can only be written inside a bracket.
  if (m_chirality[atom] != Chirality::None)
    return true;

  const unsigned char atomicNumber = m_mol.atomicNumbers()[atom];

  // A wildcard is legal bare, but it carries no implied hydrogen rule, so an
  // atom with hydrogens would have no bare form at all. Bracketing every
  // wildcard is simpler than bracketing only some of them.
  if (!hasElementSymbol(atomicNumber))
    return true;

  if (m_mol.formalCharge(atom) != 0 || m_mol.isotope(atom) != 0)
    return true;

  const int implied =
    smilesImpliedHydrogens(atomicNumber, m_bondOrderSum[atom]);
  if (implied == SmilesNotOrganicSubset)
    return true;

  // The bare form is only usable when a reader would infer exactly the
  // hydrogens this atom actually has. Where it would not -- a radical, or a
  // valence the model does not know -- the count has to be spelled out, which
  // is what keeps a methyl radical from being written as methane.
  return implied != static_cast<int>(m_implicitH[atom]);
}

bool Serializer::emitAtom(std::string& out, Index atom, std::string& error)
{
  const unsigned char atomicNumber = m_mol.atomicNumbers()[atom];
  const int charge = m_mol.formalCharge(atom);
  const unsigned short isotope = m_mol.isotope(atom);
  const bool brackets = needsBrackets(atom);

  if (brackets) {
    out += '[';
    if (isotope != 0)
      appendUnsigned(out, isotope);
  }

  // Anything without a real element symbol -- a dummy atom, a custom element,
  // or InvalidElement from an unrecognized input symbol -- becomes the SMILES
  // wildcard. Elements::symbol() would answer "Xx" for these, which is not
  // valid SMILES, and dropping the atom instead would break the atom mapping.
  if (hasElementSymbol(atomicNumber))
    out += Elements::symbol(atomicNumber);
  else
    out += '*';

  if (brackets) {
    // Chirality sits between the symbol and the hydrogen count.
    if (m_chirality[atom] == Chirality::Anticlockwise)
      out += '@';
    else if (m_chirality[atom] == Chirality::Clockwise)
      out += "@@";

    // Inside a bracket the hydrogen count is never inferred: no H means none.
    if (m_implicitH[atom] > 0) {
      out += 'H';
      if (m_implicitH[atom] > 1)
        appendUnsigned(out, m_implicitH[atom]);
    }

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
  }

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
    out += bondSymbol(m_closures[c].bond, atom);
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

      const Index parent = frame.atom;
      const Child child = m_children[frame.child];
      frame.child = child.next;

      // Every child but the last is a branch; the last one continues the
      // chain, which is what keeps the output free of redundant parentheses.
      const bool branch = (child.next != MaxIndex);
      if (branch)
        smiles += '(';
      smiles += bondSymbol(child.bond, parent);
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

  if (molecule.atomCount() == 0)
    return true;

  Serializer serializer(molecule, effectiveHydrogenMode(), m_atomMaps);
  if (!serializer.run(smiles, m_error)) {
    smiles.clear();
    return false;
  }

  return true;
}

} // namespace Avogadro::Io
