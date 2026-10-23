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
     * search order; they never change which solutions are valid. With no
     * geometric information leave the defaults (preferred = capacity,
     * score = 0), which tries the highest order first in edge order.
     */
    unsigned char preferred = 255; //!< 255 means "capacity".
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

struct BondOrderSolution
{
  /** One entry per edge: the extra order assigned, valid where the edge's
   * component was solved and zero otherwise. */
  std::vector<unsigned char> extra;

  /** One entry per vertex: the connected component it belongs to, or MaxIndex
   * for a vertex with no demand and no edges. */
  std::vector<Index> component;

  /** One entry per component: whether it was solved. */
  std::vector<bool> componentSolved;

  /** One entry per FAILED component, in component order: the vertex at which
   * the contradiction was found (for an odd total, the first vertex with
   * demand), or MaxIndex if the step budget ran out. */
  std::vector<Index> culprits;

  /** Parallel to culprits: why each failed component failed. */
  std::vector<BondOrderFailure> reasons;

  bool success() const { return culprits.empty(); }
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
 * vertex. Ordinary conjugated systems, fused aromatics included, resolve by
 * propagation alone.
 */
BondOrderSolution solveBondOrders(const BondOrderProblem& problem,
                                  std::size_t stepBudget);

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_BONDORDERSOLVER_P_H
