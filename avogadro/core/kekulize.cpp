/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "kekulize.h"

#include "mdlvalence_p.h"
#include "molecule.h"

#include <string>
#include <utility>

namespace Avogadro::Core {

namespace {

/**
 * A ceiling on backtracking steps, so a pathological input fails cleanly
 * instead of hanging. Ordinary fused aromatics never approach it: they
 * resolve through forced moves alone, with no backtracking at all.
 */
constexpr std::size_t MaxBacktrackSteps = 300000;

/**
 * Solves the "which aromatic bonds are double" problem for one molecule.
 *
 * The state is a set of candidate edges (aromatic bonds whose both endpoints
 * still need a double bond) with a trail-based undo log, so that both the
 * forced-move propagation and the backtracking search share one commit
 * routine, and the search can walk back a failed guess without recursion.
 */
class Solver
{
public:
  explicit Solver(const Molecule& molecule,
                  const std::vector<bool>& aromaticBonds)
    : m_pairs(molecule.bondPairs()), m_aromaticBonds(aromaticBonds),
      m_atomCount(molecule.atomCount()), m_bondCount(molecule.bondCount()),
      m_needsDouble(m_atomCount, false), m_alive(m_bondCount, false),
      m_committed(m_bondCount, false), m_satisfied(m_atomCount, false),
      m_degree(m_atomCount, 0), m_candidates(m_atomCount)
  {
    classify(molecule);
    buildCandidates();
  }

  /** Runs the whole algorithm. See kekulize() for what the result means. */
  bool solve(Index* failedAtom)
  {
    std::vector<Index> queue;
    Index contradiction = MaxIndex;

    for (Index atom = 0; atom < m_atomCount; ++atom) {
      if (!m_needsDouble[atom])
        continue;
      if (m_degree[atom] == 0) {
        if (failedAtom != nullptr)
          *failedAtom = atom;
        return false;
      }
      if (m_degree[atom] == 1)
        queue.push_back(atom);
    }

    if (!propagate(queue, contradiction)) {
      if (failedAtom != nullptr)
        *failedAtom = contradiction;
      return false;
    }

    return backtrack(failedAtom);
  }

  /** One entry per bond: true where this bond was committed as double. */
  const std::vector<bool>& committed() const { return m_committed; }

private:
  /** Step 1: which atoms need exactly one double bond. See kekulize.h. */
  void classify(const Molecule& molecule)
  {
    std::vector<unsigned int> aromaticCount(m_atomCount, 0);
    std::vector<unsigned int> otherOrderSum(m_atomCount, 0);
    const Array<unsigned char>& orders = molecule.bondOrders();

    for (Index bond = 0; bond < m_bondCount; ++bond) {
      const Index a = m_pairs[bond].first;
      const Index b = m_pairs[bond].second;
      if (m_aromaticBonds[bond]) {
        ++aromaticCount[a];
        ++aromaticCount[b];
      } else {
        otherOrderSum[a] += orders[bond];
        otherOrderSum[b] += orders[bond];
      }
    }

    const Array<unsigned char>& numbers = molecule.atomicNumbers();
    for (Index atom = 0; atom < m_atomCount; ++atom) {
      if (aromaticCount[atom] == 0)
        continue; // Not part of an aromatic system at all.

      // "current" is a bond order sum, not a bond count: non-aromatic bonds
      // contribute their real order, and each aromatic bond counts as 1.
      // atomValence() takes that sum as its selector among the valences an
      // element has (nitrogen's 3 and 5, sulfur's 2, 4 and 6).
      const unsigned int current = otherOrderSum[atom] + aromaticCount[atom];
      const unsigned int target =
        atomValence(numbers[atom], molecule.formalCharge(atom), current);
      // The atom needs a double bond when it has room for one more unit of
      // bond order. An overbonded atom -- target < current, from bad input --
      // also fails this test, and so is simply treated as not needing a
      // double bond rather than as a separate error case.
      m_needsDouble[atom] = (current + 1 <= target);
    }
  }

  /** Step 2 setup: aromatic bonds between two atoms that both need one. */
  void buildCandidates()
  {
    for (Index bond = 0; bond < m_bondCount; ++bond) {
      if (!m_aromaticBonds[bond])
        continue;
      const Index a = m_pairs[bond].first;
      const Index b = m_pairs[bond].second;
      if (!m_needsDouble[a] || !m_needsDouble[b])
        continue;
      m_alive[bond] = true;
      m_candidates[a].push_back(bond);
      m_candidates[b].push_back(bond);
      ++m_degree[a];
      ++m_degree[b];
    }
  }

  Index otherEnd(Index bond, Index atom) const
  {
    return (m_pairs[bond].first == atom) ? m_pairs[bond].second
                                         : m_pairs[bond].first;
  }

  // ------------------------------------------------------------------
  // Trail: every mutation the search makes is logged here with its previous
  // value, so undoTo() can walk a failed guess back without recursion.

  enum class TrailKind
  {
    Alive,
    Committed,
    Satisfied,
    Degree
  };

  struct TrailEntry
  {
    TrailKind kind;
    Index index;
    int previous;
  };

  std::vector<TrailEntry> m_trail;

  void setAlive(Index bond, bool value)
  {
    m_trail.push_back({ TrailKind::Alive, bond, m_alive[bond] ? 1 : 0 });
    m_alive[bond] = value;
  }

  void setCommitted(Index bond)
  {
    m_trail.push_back(
      { TrailKind::Committed, bond, m_committed[bond] ? 1 : 0 });
    m_committed[bond] = true;
  }

  void setSatisfied(Index atom)
  {
    m_trail.push_back(
      { TrailKind::Satisfied, atom, m_satisfied[atom] ? 1 : 0 });
    m_satisfied[atom] = true;
  }

  void decrementDegree(Index atom)
  {
    m_trail.push_back({ TrailKind::Degree, atom, m_degree[atom] });
    --m_degree[atom];
  }

  void undoTo(size_t mark)
  {
    while (m_trail.size() > mark) {
      const TrailEntry entry = m_trail.back();
      m_trail.pop_back();
      switch (entry.kind) {
        case TrailKind::Alive:
          m_alive[entry.index] = entry.previous != 0;
          break;
        case TrailKind::Committed:
          m_committed[entry.index] = entry.previous != 0;
          break;
        case TrailKind::Satisfied:
          m_satisfied[entry.index] = entry.previous != 0;
          break;
        case TrailKind::Degree:
          m_degree[entry.index] = entry.previous;
          break;
      }
    }
  }

  // ------------------------------------------------------------------
  // Committing an edge as double removes every other candidate at either
  // endpoint, since both are now satisfied; a neighbour left with a single
  // remaining candidate becomes forced in turn, which is what makes ordinary
  // fused aromatics resolve without any backtracking at all.

  /** Kills every other candidate at @a hub, queuing or failing its far ends. */
  bool removeRivals(Index hub, Index keepBond, std::vector<Index>& queue,
                    Index& contradiction)
  {
    for (Index rival : m_candidates[hub]) {
      if (rival == keepBond || !m_alive[rival])
        continue;
      setAlive(rival, false);
      const Index far = otherEnd(rival, hub);
      if (m_satisfied[far])
        continue;
      decrementDegree(far);
      if (m_degree[far] == 0) {
        contradiction = far;
        return false;
      }
      if (m_degree[far] == 1)
        queue.push_back(far);
    }
    return true;
  }

  bool commitAndCascade(Index bond, std::vector<Index>& queue,
                        Index& contradiction)
  {
    const Index a = m_pairs[bond].first;
    const Index b = m_pairs[bond].second;
    setAlive(bond, false);
    setCommitted(bond);
    setSatisfied(a);
    setSatisfied(b);
    if (!removeRivals(a, bond, queue, contradiction))
      return false;
    if (!removeRivals(b, bond, queue, contradiction))
      return false;
    return true;
  }

  /** Drains a queue of atoms forced down to exactly one candidate. */
  bool propagate(std::vector<Index>& queue, Index& contradiction)
  {
    while (!queue.empty()) {
      const Index atom = queue.back();
      queue.pop_back();
      if (m_satisfied[atom])
        continue;
      if (m_degree[atom] == 0) {
        contradiction = atom;
        return false;
      }
      if (m_degree[atom] != 1)
        continue; // No longer forced -- an earlier step already used it up.

      Index bond = MaxIndex;
      for (Index candidate : m_candidates[atom]) {
        if (m_alive[candidate]) {
          bond = candidate;
          break;
        }
      }
      if (bond == MaxIndex) { // Degree and candidate list disagree: bail out.
        contradiction = atom;
        return false;
      }
      if (!commitAndCascade(bond, queue, contradiction))
        return false;
    }
    return true;
  }

  /** The unsatisfied atom needing a double bond with the fewest options. */
  Index pickMostConstrained() const
  {
    Index best = MaxIndex;
    int bestDegree = 0;
    for (Index atom = 0; atom < m_atomCount; ++atom) {
      if (!m_needsDouble[atom] || m_satisfied[atom])
        continue;
      if (best == MaxIndex || m_degree[atom] < bestDegree) {
        best = atom;
        bestDegree = m_degree[atom];
      }
    }
    return best;
  }

  std::vector<Index> aliveEdgesAt(Index atom) const
  {
    std::vector<Index> result;
    for (Index bond : m_candidates[atom]) {
      if (m_alive[bond])
        result.push_back(bond);
    }
    return result;
  }

  // ------------------------------------------------------------------
  // Step 3: bounded backtracking, explicit stack rather than recursion so a
  // large fused system cannot overflow the call stack.

  struct Frame
  {
    std::vector<Index> options;
    size_t cursor = 0;
    size_t trailMark = 0;
  };

  bool backtrack(Index* failedAtom)
  {
    std::vector<Frame> stack;
    std::size_t steps = 0;
    Index lastContradiction = MaxIndex;
    bool descending = true;

    for (;;) {
      if (descending) {
        const Index atom = pickMostConstrained();
        if (atom == MaxIndex)
          break; // Nothing left unsatisfied: every candidate is resolved.

        if (steps >= MaxBacktrackSteps) {
          if (failedAtom != nullptr)
            *failedAtom = MaxIndex; // A resource limit, not one atom's fault.
          return false;
        }
        ++steps;

        Frame frame;
        frame.options = aliveEdgesAt(atom);
        frame.cursor = 0;
        frame.trailMark = m_trail.size();
        stack.push_back(std::move(frame));
        descending = false;
      }

      Frame& top = stack.back();
      if (top.cursor >= top.options.size()) {
        // Every option at this atom has failed: undo it entirely and let the
        // atom that chose the edge leading here try its next option.
        undoTo(top.trailMark);
        stack.pop_back();
        if (stack.empty()) {
          if (failedAtom != nullptr)
            *failedAtom = lastContradiction;
          return false;
        }
        ++stack.back().cursor;
        continue;
      }

      // Clear whatever the previous cursor left, which also restores m_alive
      // to exactly the state options was collected in -- so every option is
      // still alive here and there is nothing to re-check.
      undoTo(top.trailMark);
      const Index bond = top.options[top.cursor];

      std::vector<Index> queue;
      Index contradiction = MaxIndex;
      const bool ok = commitAndCascade(bond, queue, contradiction) &&
                      propagate(queue, contradiction);
      if (ok) {
        descending = true;
      } else {
        lastContradiction = contradiction;
        undoTo(top.trailMark);
        ++top.cursor;
      }
    }

    return true;
  }

  const Array<std::pair<Index, Index>>& m_pairs;
  const std::vector<bool>& m_aromaticBonds;
  Index m_atomCount;
  Index m_bondCount;

  std::vector<bool> m_needsDouble;
  std::vector<bool> m_alive;     //!< Still-available candidate edges.
  std::vector<bool> m_committed; //!< Result: which edges became double bonds.
  std::vector<bool> m_satisfied; //!< Atoms whose double bond is decided.
  std::vector<int> m_degree;     //!< Remaining alive candidates per atom.
  std::vector<std::vector<Index>> m_candidates; //!< Candidate bonds per atom.
};

} // namespace

bool kekulize(Molecule& molecule, const std::vector<bool>& aromaticBonds,
              Index* failedAtom)
{
  if (failedAtom != nullptr)
    *failedAtom = MaxIndex;

  const Index bondCount = molecule.bondCount();
  if (aromaticBonds.size() != bondCount)
    return false; // Caller error: one entry per bond is required.

  bool anyAromatic = false;
  for (bool aromatic : aromaticBonds) {
    if (aromatic) {
      anyAromatic = true;
      break;
    }
  }
  if (!anyAromatic)
    return true; // Nothing to do, and nothing to touch.

  Solver solver(molecule, aromaticBonds);
  if (!solver.solve(failedAtom))
    return false;

  // Step 4: nothing is written until the whole assignment has succeeded.
  const std::vector<bool>& committed = solver.committed();
  for (Index bond = 0; bond < bondCount; ++bond) {
    if (aromaticBonds[bond])
      molecule.setBondOrder(bond, committed[bond] ? 2 : 1);
  }
  return true;
}

std::string kekulizeFailureMessage(Index failedAtom)
{
  std::string message =
    "Could not kekulize aromatic bonds: no valid arrangement of alternating "
    "single and double bonds exists";
  // MaxIndex means the failure was not attributable to any one atom.
  if (failedAtom != MaxIndex)
    message += " that satisfies atom " + std::to_string(failedAtom);
  return message + ".";
}

} // namespace Avogadro::Core
