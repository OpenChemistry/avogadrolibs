/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "kekulize.h"

#include "bondordersolver_p.h"
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
 * Step 1: which atoms need exactly one double bond. See kekulize.h.
 *
 * @return one entry per atom, true where the atom is incident to an aromatic
 * bond and still has room for one more unit of bond order.
 */
std::vector<bool> classify(const Molecule& molecule,
                           const std::vector<bool>& aromaticBonds)
{
  const Index atomCount = molecule.atomCount();
  const Index bondCount = molecule.bondCount();
  const Array<std::pair<Index, Index>>& pairs = molecule.bondPairs();
  std::vector<unsigned int> aromaticCount(atomCount, 0);
  std::vector<unsigned int> otherOrderSum(atomCount, 0);
  const Array<unsigned char>& orders = molecule.bondOrders();

  for (Index bond = 0; bond < bondCount; ++bond) {
    const Index a = pairs[bond].first;
    const Index b = pairs[bond].second;
    if (aromaticBonds[bond]) {
      ++aromaticCount[a];
      ++aromaticCount[b];
    } else {
      otherOrderSum[a] += orders[bond];
      otherOrderSum[b] += orders[bond];
    }
  }

  std::vector<bool> needsDouble(atomCount, false);
  const Array<unsigned char>& numbers = molecule.atomicNumbers();
  for (Index atom = 0; atom < atomCount; ++atom) {
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
    needsDouble[atom] = (current + 1 <= target);
  }
  return needsDouble;
}

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

  // Step 2: the candidates are the aromatic bonds between two atoms that both
  // need a double bond. Each atom needs exactly one, and a bond can carry at
  // most one extra order, so this is the u_v in {0, 1}, capacity 1 case of
  // the general bond order problem.
  const std::vector<bool> needsDouble = classify(molecule, aromaticBonds);
  const Array<std::pair<Index, Index>>& pairs = molecule.bondPairs();

  BondOrderProblem problem;
  problem.demand.assign(molecule.atomCount(), 0);
  for (Index atom = 0; atom < molecule.atomCount(); ++atom)
    problem.demand[atom] = needsDouble[atom] ? 1 : 0;

  std::vector<Index> bondOfEdge;
  for (Index bond = 0; bond < bondCount; ++bond) {
    if (!aromaticBonds[bond])
      continue;
    const Index a = pairs[bond].first;
    const Index b = pairs[bond].second;
    if (!needsDouble[a] || !needsDouble[b])
      continue;
    BondOrderProblem::Edge edge;
    edge.a = a;
    edge.b = b;
    edge.capacity = 1;
    problem.edges.push_back(edge);
    bondOfEdge.push_back(bond);
  }

  // Step 3: forced moves, then bounded backtracking.
  const BondOrderSolution solution =
    solveBondOrders(problem, MaxBacktrackSteps);
  if (!solution.success()) {
    if (failedAtom != nullptr)
      *failedAtom = solution.culprits.front();
    return false;
  }

  // Step 4: nothing is written until the whole assignment has succeeded.
  for (Index bond = 0; bond < bondCount; ++bond) {
    if (aromaticBonds[bond])
      molecule.setBondOrder(bond, 1);
  }
  for (std::size_t edge = 0; edge < bondOfEdge.size(); ++edge) {
    if (solution.extra[edge] > 0)
      molecule.setBondOrder(bondOfEdge[edge], 2);
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
