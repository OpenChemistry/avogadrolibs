/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_BONDORDERSOLVER_P_H
#define AVOGADRO_CORE_BONDORDERSOLVER_P_H

#include "avogadrocore.h"

#include <cstddef>
#include <vector>

namespace Avogadro::Core {

/**
 * The degree-constrained subgraph problem behind bond order perception and
 * kekulization: give every candidate edge e an extra bond order x_e in
 * [0, capacity_e] so that, at every vertex v, the x_e of its edges sum to
 * exactly demand_v.
 *
 * Vertices are caller-defined indices (atom indices); a vertex with no demand
 * and no edges is simply ignored.
 */
struct BondOrderProblem
{
  struct Edge
  {
    Index a = 0;
    Index b = 0;
    unsigned char capacity = 1; //!< Largest extra order this edge may carry.

    /**
     * The extra order the caller would like to try first (0 to capacity), and
     * how strongly it likes the edge to be raised at all: edges at a vertex
     * are branched on in order of decreasing @p score. Both only steer the
     * search order; they never change which solutions are valid. Callers
     * always set @p preferred. With no geometric information use
     * preferred = capacity and score = 0, which tries the highest order
     * first in edge order.
     */
    unsigned char preferred = 0;
    double score = 0.0;
  };

  std::vector<unsigned char> demand; //!< One entry per vertex.
  std::vector<Edge> edges;
};

/** Why a component could not be solved. */
enum class BondOrderFailure
{
  Contradiction,  //!< propagation or search showed no assignment exists
  StepLimit,      //!< the step budget ran out before an answer was found
  OddUnsaturation //!< total demand is odd, so no assignment can exist
};

/** A component that could not be solved. */
struct ComponentFailure
{
  /** The vertex at which the contradiction was found (for an odd total, the
   * first vertex with demand), or MaxIndex if the step budget ran out. */
  Index culprit = MaxIndex;
  BondOrderFailure reason = BondOrderFailure::Contradiction;

  /** The component's vertices that still have demand, in increasing order. */
  std::vector<Index> vertices;
};

struct BondOrderSolution
{
  /** One entry per edge: the extra order assigned, valid where the edge's
   * component was solved and zero otherwise. */
  std::vector<unsigned char> extra;

  /** One entry per failed component, in component order (by first vertex). */
  std::vector<ComponentFailure> failures;

  bool success() const { return failures.empty(); }
};

/**
 * Solves every connected component of @a problem independently, so that one
 * unsatisfiable component cannot spoil another, and each component gets its
 * own budget of @a stepBudget branching steps.
 *
 * The search is constraint propagation (bounds on each edge's extra order,
 * tightened until nothing changes: an atom whose demand equals the total
 * capacity of its open edges forces them all, an atom with no demand left
 * zeroes them all) with bounded backtracking over the most constrained
 * vertex. Isolated multiple bonds resolve by propagation alone; rings and
 * other conjugated systems need a few branching steps (benzene one, biphenyl
 * two, coronene five), which then propagate to settle the rest.
 */
BondOrderSolution solveBondOrders(const BondOrderProblem& problem,
                                  std::size_t stepBudget);

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_BONDORDERSOLVER_P_H
