/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bondordersolver_p.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <numeric>
#include <utility>

namespace Avogadro::Core {

namespace {

/**
 * Solves one problem, one connected component at a time.
 *
 * Every edge carries a closed interval [lo, hi] of extra orders it may still
 * take; an edge is decided once lo == hi. All mutations of those intervals go
 * through setBounds(), which logs the previous interval on a trail, so the
 * forced-move propagation and the backtracking search share one routine and
 * the search can walk a failed guess back without recursion.
 */
class Solver
{
public:
  explicit Solver(const BondOrderProblem& problem)
    : m_problem(problem), m_vertexCount(problem.demand.size()),
      m_lo(problem.edges.size(), 0), m_hi(problem.edges.size(), 0),
      m_sumLo(m_vertexCount, 0), m_sumHi(m_vertexCount, 0),
      m_inQueue(m_vertexCount, false), m_incidentStart(m_vertexCount + 1, 0)
  {
    for (std::size_t e = 0; e < problem.edges.size(); ++e) {
      const BondOrderProblem::Edge& edge = problem.edges[e];
      m_hi[e] = edge.capacity;
      ++m_incidentStart[edge.a + 1];
      ++m_incidentStart[edge.b + 1];
      m_sumHi[edge.a] += edge.capacity;
      m_sumHi[edge.b] += edge.capacity;
    }

    // Edges at each vertex, in one flat array (offsets are a prefix sum of
    // the degrees). Filling in ascending edge order keeps every vertex's
    // slice in ascending edge order, which the search order depends on.
    for (std::size_t v = 0; v < m_vertexCount; ++v)
      m_incidentStart[v + 1] += m_incidentStart[v];
    m_incidentEdges.resize(m_incidentStart[m_vertexCount]);
    std::vector<std::size_t> fill(m_incidentStart.begin(),
                                  m_incidentStart.end() - 1);
    for (std::size_t e = 0; e < problem.edges.size(); ++e) {
      m_incidentEdges[fill[problem.edges[e].a]++] = e;
      m_incidentEdges[fill[problem.edges[e].b]++] = e;
    }
  }

  BondOrderSolution solve(std::size_t stepBudget)
  {
    BondOrderSolution solution;
    solution.extra.assign(m_problem.edges.size(), 0);

    std::vector<std::vector<Index>> componentVertices;
    std::vector<std::vector<std::size_t>> componentEdges;
    findComponents(componentVertices, componentEdges);

    for (std::size_t c = 0; c < componentVertices.size(); ++c) {
      ComponentFailure failure;
      if (solveComponent(componentVertices[c], stepBudget, failure.culprit,
                         failure.reason)) {
        for (std::size_t e : componentEdges[c])
          solution.extra[e] = m_lo[e];
      } else {
        for (Index v : componentVertices[c]) {
          if (m_problem.demand[v] > 0)
            failure.vertices.push_back(v);
        }
        solution.failures.push_back(std::move(failure));
      }
    }
    return solution;
  }

private:
  // ------------------------------------------------------------------
  // Components: union-find over the edge endpoints. A vertex that wants
  // order but has no edge at all is a component of its own, and fails.

  static Index findRoot(std::vector<Index>& parent, Index v)
  {
    while (parent[v] != v) {
      parent[v] = parent[parent[v]];
      v = parent[v];
    }
    return v;
  }

  void findComponents(std::vector<std::vector<Index>>& vertices,
                      std::vector<std::vector<std::size_t>>& edges) const
  {
    std::vector<Index> componentOf(m_vertexCount, MaxIndex);
    std::vector<Index> parent(m_vertexCount);
    std::iota(parent.begin(), parent.end(), Index(0));
    for (const BondOrderProblem::Edge& edge : m_problem.edges) {
      const Index ra = findRoot(parent, edge.a);
      const Index rb = findRoot(parent, edge.b);
      if (ra != rb)
        parent[std::max(ra, rb)] = std::min(ra, rb);
    }

    // The root is the smallest vertex index, so components come out ordered
    // by their first vertex.
    std::vector<Index> idOfRoot(m_vertexCount, MaxIndex);
    for (Index v = 0; v < m_vertexCount; ++v) {
      if (m_incidentStart[v] == m_incidentStart[v + 1] &&
          m_problem.demand[v] == 0)
        continue;
      const Index root = findRoot(parent, v);
      if (idOfRoot[root] == MaxIndex) {
        idOfRoot[root] = vertices.size();
        vertices.emplace_back();
        edges.emplace_back();
      }
      componentOf[v] = idOfRoot[root];
      vertices[idOfRoot[root]].push_back(v);
    }
    for (std::size_t e = 0; e < m_problem.edges.size(); ++e)
      edges[componentOf[m_problem.edges[e].a]].push_back(e);
  }

  /** The edges at a vertex, in ascending edge order. */
  struct EdgeRange
  {
    const std::size_t* first;
    const std::size_t* last;
    const std::size_t* begin() const { return first; }
    const std::size_t* end() const { return last; }
  };

  EdgeRange incident(Index v) const
  {
    return { m_incidentEdges.data() + m_incidentStart[v],
             m_incidentEdges.data() + m_incidentStart[v + 1] };
  }

  // ------------------------------------------------------------------
  // Trail

  struct TrailEntry
  {
    std::size_t edge;
    unsigned char lo;
    unsigned char hi;
  };

  void applyBounds(std::size_t e, unsigned char lo, unsigned char hi)
  {
    const BondOrderProblem::Edge& edge = m_problem.edges[e];
    const int dLo = int(lo) - int(m_lo[e]);
    const int dHi = int(hi) - int(m_hi[e]);
    m_sumLo[edge.a] += dLo;
    m_sumLo[edge.b] += dLo;
    m_sumHi[edge.a] += dHi;
    m_sumHi[edge.b] += dHi;
    m_lo[e] = lo;
    m_hi[e] = hi;
  }

  void setBounds(std::size_t e, unsigned char lo, unsigned char hi)
  {
    m_trail.push_back({ e, m_lo[e], m_hi[e] });
    applyBounds(e, lo, hi);
  }

  void undoTo(std::size_t mark)
  {
    while (m_trail.size() > mark) {
      const TrailEntry entry = m_trail.back();
      m_trail.pop_back();
      applyBounds(entry.edge, entry.lo, entry.hi);
    }
  }

  // ------------------------------------------------------------------
  // Propagation. At a vertex with demand D, an edge e must carry at least
  // D - (sum of the other edges' hi) and at most D - (sum of the other
  // edges' lo). This one rule covers all the forced moves:
  //  - D equals the total capacity of the open edges: lo is raised to hi on
  //    every one of them (all full);
  //  - D is already met by the decided edges: hi drops to lo on the rest
  //    (all zero);
  //  - a single open edge: lo = hi = whatever is still owed.
  // A vertex whose D falls outside [sum of lo, sum of hi] is a contradiction.

  void enqueue(Index v)
  {
    if (!m_inQueue[v]) {
      m_inQueue[v] = true;
      m_queue.push_back(v);
    }
  }

  void clearQueue()
  {
    for (Index v : m_queue)
      m_inQueue[v] = false;
    m_queue.clear();
  }

  bool propagate(Index& contradiction)
  {
    while (!m_queue.empty()) {
      const Index v = m_queue.back();
      m_queue.pop_back();
      m_inQueue[v] = false;

      const int demand = m_problem.demand[v];
      for (std::size_t e : incident(v)) {
        if (m_sumLo[v] > demand || m_sumHi[v] < demand) {
          contradiction = v;
          clearQueue();
          return false;
        }
        const int lo = m_lo[e];
        const int hi = m_hi[e];
        const int newHi = std::min(hi, demand - (m_sumLo[v] - lo));
        const int newLo = std::max(lo, demand - (m_sumHi[v] - hi));
        if (newLo != lo || newHi != hi) {
          setBounds(e, static_cast<unsigned char>(newLo),
                    static_cast<unsigned char>(newHi));
          enqueue(m_problem.edges[e].a);
          enqueue(m_problem.edges[e].b);
        }
      }
      if (m_sumLo[v] > demand || m_sumHi[v] < demand) {
        contradiction = v;
        clearQueue();
        return false;
      }
    }
    return true;
  }

  // ------------------------------------------------------------------
  // Search

  /** Number of edges at @a v that are not decided yet. */
  int openEdges(Index v) const
  {
    int count = 0;
    for (std::size_t e : incident(v)) {
      if (m_lo[e] < m_hi[e])
        ++count;
    }
    return count;
  }

  /** The vertex with the fewest (but at least one) undecided edges. */
  Index pickMostConstrained(const std::vector<Index>& vertices) const
  {
    Index best = MaxIndex;
    int bestOpen = 0;
    for (Index v : vertices) {
      const int open = openEdges(v);
      if (open == 0)
        continue;
      if (best == MaxIndex || open < bestOpen) {
        best = v;
        bestOpen = open;
      }
    }
    return best;
  }

  /**
   * Of the undecided edges at @a v, the one the caller scores highest, i.e.
   * the one most likely to carry extra order. Ties go to the first in edge
   * order, so the result is deterministic.
   */
  std::size_t pickEdge(Index v) const
  {
    std::size_t best = 0;
    bool found = false;
    for (std::size_t e : incident(v)) {
      if (m_lo[e] == m_hi[e])
        continue;
      if (!found || m_problem.edges[e].score > m_problem.edges[best].score) {
        best = e;
        found = true;
      }
    }
    return best;
  }

  /** At most capacity + 1 = 3 values; a fixed array avoids an allocation. */
  struct Values
  {
    std::array<unsigned char, 4> data{};
    std::size_t count = 0;
  };

  /** The values still open on edge @a e, the preferred one first. */
  Values orderedValues(std::size_t e) const
  {
    const int preferred = m_problem.edges[e].preferred;
    Values values;
    for (int value = m_lo[e]; value <= m_hi[e]; ++value)
      values.data[values.count++] = static_cast<unsigned char>(value);
    // Closest to the preferred value first; of two equally close, the higher.
    std::stable_sort(values.data.begin(), values.data.begin() + values.count,
                     [preferred](unsigned char x, unsigned char y) {
                       const int dx = std::abs(int(x) - preferred);
                       const int dy = std::abs(int(y) - preferred);
                       return dx != dy ? dx < dy : x > y;
                     });
    return values;
  }

  struct Frame
  {
    std::size_t edge = 0;
    Values values;
    std::size_t cursor = 0;
    std::size_t trailMark = 0;
  };

  bool solveComponent(const std::vector<Index>& vertices,
                      std::size_t stepBudget, Index& culprit,
                      BondOrderFailure& reason)
  {
    // A necessary condition, checked before any search: every unit of extra
    // order on an edge is counted once at each of its two ends, so the
    // demands of a component must add up to an even number. An odd total
    // (an unpaired electron, or a site that needs a charge) can never be
    // met, and without this the search would try every arrangement before
    // giving up.
    unsigned int totalDemand = 0;
    for (Index v : vertices)
      totalDemand += m_problem.demand[v];
    if (totalDemand % 2 != 0) {
      for (Index v : vertices) {
        if (m_problem.demand[v] > 0) {
          culprit = v;
          break;
        }
      }
      reason = BondOrderFailure::OddUnsaturation;
      return false;
    }

    m_trail.clear();
    clearQueue();
    for (Index v : vertices)
      enqueue(v);

    Index contradiction = MaxIndex;
    if (!propagate(contradiction)) {
      // Includes the other necessary condition, that an atom's demand cannot
      // exceed the total capacity of its edges: propagation sees that at once.
      culprit = contradiction;
      return false;
    }

    // Explicit stack rather than recursion, so a large fused system cannot
    // overflow the call stack.
    std::vector<Frame> stack;
    std::size_t steps = 0;
    Index lastContradiction = MaxIndex;
    bool descending = true;

    for (;;) {
      if (descending) {
        const Index v = pickMostConstrained(vertices);
        if (v == MaxIndex)
          return true; // Every edge is decided.

        if (steps >= stepBudget) {
          culprit = MaxIndex; // A resource limit, not one atom's fault.
          reason = BondOrderFailure::StepLimit;
          return false;
        }
        ++steps;

        Frame frame;
        frame.edge = pickEdge(v);
        frame.values = orderedValues(frame.edge);
        frame.trailMark = m_trail.size();
        stack.push_back(std::move(frame));
        descending = false;
      }

      Frame& top = stack.back();
      if (top.cursor >= top.values.count) {
        // Every value of this edge has failed: undo it entirely and let the
        // edge decided before it try its next value.
        undoTo(top.trailMark);
        stack.pop_back();
        if (stack.empty()) {
          culprit = lastContradiction;
          return false;
        }
        ++stack.back().cursor;
        continue;
      }

      // Clear whatever the previous value left, which also restores the
      // intervals to the state the value list was collected in.
      undoTo(top.trailMark);
      const unsigned char value = top.values.data[top.cursor];
      setBounds(top.edge, value, value);
      enqueue(m_problem.edges[top.edge].a);
      enqueue(m_problem.edges[top.edge].b);
      if (propagate(contradiction)) {
        descending = true;
      } else {
        lastContradiction = contradiction;
        undoTo(top.trailMark);
        ++top.cursor;
      }
    }
  }

  const BondOrderProblem& m_problem;
  std::size_t m_vertexCount;

  std::vector<unsigned char> m_lo;
  std::vector<unsigned char> m_hi;
  std::vector<int> m_sumLo; //!< Per vertex: sum of lo over its edges.
  std::vector<int> m_sumHi; //!< Per vertex: sum of hi over its edges.
  std::vector<bool> m_inQueue;
  std::vector<Index> m_queue;
  std::vector<std::size_t> m_incidentStart; //!< CSR offsets, size n + 1.
  std::vector<std::size_t> m_incidentEdges; //!< Edges grouped by vertex.
  std::vector<TrailEntry> m_trail;
};

} // namespace

BondOrderSolution solveBondOrders(const BondOrderProblem& problem,
                                  std::size_t stepBudget)
{
  Solver solver(problem);
  return solver.solve(stepBudget);
}

} // namespace Avogadro::Core
