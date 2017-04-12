/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "ringperceiver.h"

#include "molecule.h"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <limits>
#include <set>
#include <vector>

namespace Avogadro {
namespace Core {

namespace {

// === DistanceMatrix ====================================================== //
class DistanceMatrix
{
public:
  // construction and destruction
  DistanceMatrix(size_t size);
  ~DistanceMatrix();

  // operators
  size_t operator()(size_t i, size_t j) const;
  size_t& operator()(size_t i, size_t j);

private:
  size_t m_size;
  size_t* m_values;
};

DistanceMatrix::DistanceMatrix(size_t size)
{
  m_size = size;
  m_values = new size_t[size * size];
  memset(m_values, 0, size * size * sizeof(size_t));
}

DistanceMatrix::~DistanceMatrix()
{
  delete[] m_values;
}

size_t DistanceMatrix::operator()(size_t i, size_t j) const
{
  return m_values[i * m_size + j];
}

size_t& DistanceMatrix::operator()(size_t i, size_t j)
{
  return m_values[i * m_size + j];
}

// === PidMatrix =========================================================== //
// The PidMatrix class implements a path-included distance matrix.
class PidMatrix
{
public:
  // construction and destruction
  PidMatrix(size_t size);
  ~PidMatrix();

  // paths
  std::vector<std::vector<size_t>>& paths(size_t i, size_t j);
  void addPaths(size_t i, size_t j,
                const std::vector<std::vector<size_t>>& paths);
  std::vector<std::vector<size_t>> splice(size_t i, size_t j, size_t k);

  // operators
  std::vector<std::vector<size_t>>& operator()(size_t i, size_t j);

private:
  size_t m_size;
  std::vector<std::vector<size_t>>* m_values;
};

// --- Construction and Destruction ---------------------------------------- //
PidMatrix::PidMatrix(size_t size)
{
  m_size = size;
  m_values = new std::vector<std::vector<size_t>>[ size * size ];
}

PidMatrix::~PidMatrix()
{
  delete[] m_values;
}

// --- Paths --------------------------------------------------------------- //
std::vector<std::vector<size_t>>& PidMatrix::paths(size_t i, size_t j)
{
  return m_values[i * m_size + j];
}

void PidMatrix::addPaths(size_t i, size_t j,
                         const std::vector<std::vector<size_t>>& p)
{
  std::vector<std::vector<size_t>>& current = m_values[i * m_size + j];
  current.insert(current.end(), p.begin(), p.end());
}

std::vector<std::vector<size_t>>& PidMatrix::operator()(size_t i, size_t j)
{
  return paths(i, j);
}

std::vector<std::vector<size_t>> PidMatrix::splice(size_t i, size_t j, size_t k)
{
  std::vector<std::vector<size_t>> splicedPaths;

  std::vector<std::vector<size_t>> ijPaths = paths(i, j);
  std::vector<std::vector<size_t>> jkPaths = paths(j, k);

  if (ijPaths.empty() && jkPaths.empty()) {
    std::vector<size_t> path;
    path.push_back(j);
    splicedPaths.push_back(path);
  } else if (ijPaths.empty()) {
    for (std::vector<std::vector<size_t>>::iterator iter = jkPaths.begin();
         iter != jkPaths.end(); ++iter) {
      std::vector<size_t> path;
      path.push_back(j);
      path.insert(path.end(), iter->begin(), iter->end());
      splicedPaths.push_back(path);
    }
  } else if (jkPaths.empty()) {
    for (std::vector<std::vector<size_t>>::iterator iter = ijPaths.begin();
         iter != ijPaths.end(); ++iter) {
      std::vector<size_t> path = *iter;
      path.push_back(j);
      splicedPaths.push_back(path);
    }
  } else {
    for (std::vector<std::vector<size_t>>::iterator ijIter = ijPaths.begin();
         ijIter != ijPaths.end(); ++ijIter) {
      for (std::vector<std::vector<size_t>>::iterator jkIter = jkPaths.begin();
           jkIter != jkPaths.end(); ++jkIter) {
        std::vector<size_t> path = *ijIter;
        path.push_back(j);
        path.insert(path.end(), jkIter->begin(), jkIter->end());
        splicedPaths.push_back(path);
      }
    }
  }

  return splicedPaths;
}

// === RingCandidate ======================================================= //
class RingCandidate
{
public:
  // construction and destruction
  RingCandidate(size_t n, size_t s, size_t e);

  // properties
  size_t size() const;
  size_t start() const;
  size_t end() const;

  // static methods
  static bool compareSize(const RingCandidate& a, const RingCandidate& b);

private:
  size_t m_size;
  size_t m_start;
  size_t m_end;
};

// --- Construction and Destruction ---------------------------------------- //
RingCandidate::RingCandidate(size_t n, size_t s, size_t e)
{
  m_size = n;
  m_start = s;
  m_end = e;
}

// --- Properties ---------------------------------------------------------- //
size_t RingCandidate::size() const
{
  return m_size;
}

size_t RingCandidate::start() const
{
  return m_start;
}

size_t RingCandidate::end() const
{
  return m_end;
}

// --- Static Methods ------------------------------------------------------ //
bool RingCandidate::compareSize(const RingCandidate& a, const RingCandidate& b)
{
  return a.size() < b.size();
}

// === Sssr ================================================================ //
class Sssr
{
public:
  // construction and destruction
  Sssr();
  ~Sssr();

  // properties
  size_t size() const;
  bool isEmpty() const;

  // rings
  const std::vector<std::vector<size_t>>& rings() const;
  void append(const std::vector<size_t>& ring);
  bool isValid(const std::vector<size_t>& ring) const;
  bool isUnique(const std::vector<size_t>& ring) const;

private:
  std::vector<std::vector<size_t>> m_rings;
};

// --- Construction and Destruction ---------------------------------------- //
Sssr::Sssr()
{
}

Sssr::~Sssr()
{
}

// --- Properties ---------------------------------------------------------- //
size_t Sssr::size() const
{
  return m_rings.size();
}

bool Sssr::isEmpty() const
{
  return m_rings.empty();
}

// --- Rings --------------------------------------------------------------- //
const std::vector<std::vector<size_t>>& Sssr::rings() const
{
  return m_rings;
}

void Sssr::append(const std::vector<size_t>& ring)
{
  m_rings.push_back(ring);
}

bool Sssr::isValid(const std::vector<size_t>& ring) const
{
  // Check for any duplicate atoms.
  for (size_t i = 0; i < ring.size(); ++i)
    for (size_t j = i + 1; j < ring.size(); ++j)
      if (ring[i] == ring[j])
        return false;

  return true;
}

bool Sssr::isUnique(const std::vector<size_t>& path) const
{
  // Must be unique if sssr is empty.
  if (isEmpty())
    return true;

  // Check if a ring with the same atoms is already in the sssr.
  std::set<size_t> pathSet;
  pathSet.insert(path.begin(), path.end());

  for (std::vector<std::vector<size_t>>::const_iterator iter = m_rings.begin();
       iter != m_rings.end(); ++iter) {
    const std::vector<size_t>& ring = *iter;

    std::set<size_t> ringSet;
    ringSet.insert(ring.begin(), ring.end());

    std::vector<size_t> sortedRing(ring.begin(), ring.end());
    std::sort(sortedRing.begin(), sortedRing.end());

    std::set<size_t> intersection;
    std::set_intersection(pathSet.begin(), pathSet.end(), ringSet.begin(),
                          ringSet.end(),
                          std::inserter(intersection, intersection.begin()));

    if (intersection.size() == ring.size())
      return false;
  }

  // Build the set of bonds in the path.
  std::set<std::pair<size_t, size_t>> pathBonds;
  for (size_t i = 0; i < path.size() - 1; i++) {
    pathBonds.insert(std::make_pair(std::min(path[i], path[i + 1]),
                                    std::max(path[i], path[i + 1])));
  }

  pathBonds.insert(std::make_pair(std::min(path.front(), path.back()),
                                  std::max(path.front(), path.back())));

  // Remove bonds from path bonds that are already in a smaller ring.
  for (std::vector<std::vector<size_t>>::const_iterator iter = m_rings.begin();
       iter != m_rings.end(); ++iter) {
    const std::vector<size_t>& ring = *iter;

    if (ring.size() >= path.size())
      continue;

    for (size_t i = 0; i < ring.size(); i++) {
      pathBonds.erase(std::make_pair(std::min(ring[i], ring[i + 1]),
                                     std::max(ring[i], ring[i + 1])));
    }

    pathBonds.erase(std::make_pair(std::min(ring.front(), ring.back()),
                                   std::max(ring.front(), ring.back())));
  }

  // Check if any other ring contains the same bonds.
  for (std::vector<std::vector<size_t>>::const_iterator iter = m_rings.begin();
       iter != m_rings.end(); ++iter) {
    const std::vector<size_t>& ring = *iter;

    std::set<std::pair<size_t, size_t>> ringBonds;

    // Add ring bonds.
    for (size_t i = 0; i < ring.size() - 1; i++) {
      ringBonds.insert(std::make_pair(std::min(ring[i], ring[i + 1]),
                                      std::max(ring[i], ring[i + 1])));
    }

    // Add closure bond.
    ringBonds.insert(std::make_pair(std::min(ring.front(), ring.back()),
                                    std::max(ring.front(), ring.back())));

    // Check intersection.
    std::set<std::pair<size_t, size_t>> intersection;
    std::set_intersection(pathBonds.begin(), pathBonds.end(), ringBonds.begin(),
                          ringBonds.end(),
                          std::inserter(intersection, intersection.begin()));

    if (intersection.size() == pathBonds.size())
      return false;
  }

  return true;
}

std::vector<std::vector<size_t>> perceiveRings(const Graph& graph)
{
  size_t n = graph.size();

  size_t ringCount = graph.vertexCount() - graph.edgeCount() + 1;
  if (ringCount == 0)
    return std::vector<std::vector<size_t>>();

  // Algorithm 1 - create the distance and pid matrices.
  DistanceMatrix D(n);
  PidMatrix P(n);
  PidMatrix Pt(n);

  for (size_t i = 0; i < n; ++i) {
    for (size_t j = 0; j < n; ++j) {
      if (i == j)
        D(i, j) = 0;
      else if (graph.containsEdge(i, j))
        D(i, j) = 1;
      else
        D(i, j) = std::numeric_limits<size_t>::max() / 2; // ~ infinity
    }
  }

  for (size_t k = 0; k < n; ++k) {
    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < n; ++j) {
        if (i == j || i == k || k == j)
          continue;

        if (D(i, j) > D(i, k) + D(k, j)) {
          if (D(i, j) == D(i, k) + D(k, j) + 1)
            Pt(i, j) = P(i, j);
          else
            Pt(i, j).clear();

          D(i, j) = D(i, k) + D(k, j);
          P(i, j) = P.splice(i, k, j);
        } else if (D(i, j) == D(i, k) + D(k, j)) {
          P.addPaths(i, j, P.splice(i, k, j));
        } else if (D(i, j) == D(i, k) + D(k, j) - 1) {
          Pt.addPaths(i, j, P.splice(i, k, j));
        }
      }
    }
  }

  // Algorithm 2 - create the ring candidate set.
  std::vector<RingCandidate> candidates;
  for (size_t i = 0; i < n; i++) {
    for (size_t j = i + 1; j < n; j++) {
      if (P(i, j).size() == 1 && Pt(i, j).size() == 0) {
        continue;
      } else {
        size_t size;

        if (P(i, j).size() > 1)
          size = 2 * D(i, j);
        else
          size = 2 * D(i, j) + 1;

        if (size > 2)
          candidates.push_back(RingCandidate(size, i, j));
      }
    }
  }

  // Sort the candidates.
  std::sort(candidates.begin(), candidates.end(), RingCandidate::compareSize);

  // Algorithm 3 - find sssr from the ring candidate set.
  Sssr sssr;

  for (std::vector<RingCandidate>::iterator iter = candidates.begin();
       iter != candidates.end(); ++iter) {
    const RingCandidate& candidate = *iter;

    // odd sized ring
    if (candidate.size() & 1) {
      for (size_t i = 0; i < Pt(candidate.start(), candidate.end()).size();
           ++i) {
        std::vector<size_t> ring;
        ring.push_back(candidate.start());
        std::vector<size_t>& path = Pt(candidate.start(), candidate.end())[i];
        ring.insert(ring.end(), path.begin(), path.end());
        ring.push_back(candidate.end());
        if (!P(candidate.end(), candidate.start()).empty()) {
          path = P(candidate.end(), candidate.start())[0];
          ring.insert(ring.end(), path.begin(), path.end());
        }

        // Check if ring is valid and unique.
        if (sssr.isValid(ring) && sssr.isUnique(ring)) {
          sssr.append(ring);
          break;
        }
      }
    }

    // Even sized ring.
    else {
      for (size_t i = 0; i < P(candidate.start(), candidate.end()).size() - 1;
           ++i) {
        std::vector<size_t> ring;
        ring.push_back(candidate.start());
        std::vector<size_t>& path = P(candidate.start(), candidate.end())[i];
        ring.insert(ring.end(), path.begin(), path.end());
        ring.push_back(candidate.end());
        path = P(candidate.end(), candidate.start())[i + 1];
        ring.insert(ring.end(), path.begin(), path.end());

        // check if ring is valid and unique
        if (sssr.isValid(ring) && sssr.isUnique(ring)) {
          sssr.append(ring);
          break;
        }
      }
    }

    if (sssr.size() == ringCount)
      break;
  }

  return sssr.rings();
}

} // end anonymous namespace

RingPerceiver::RingPerceiver(const Molecule* m)
  : m_ringsPerceived(false), m_molecule(m)
{
}

RingPerceiver::~RingPerceiver()
{
}

void RingPerceiver::setMolecule(const Molecule* m)
{
  m_molecule = m;
  m_ringsPerceived = false;
}

const Molecule* RingPerceiver::molecule() const
{
  return m_molecule;
}

std::vector<std::vector<size_t>>& RingPerceiver::rings()
{
  if (!m_ringsPerceived) {
    if (m_molecule)
      m_rings = perceiveRings(m_molecule->graph());
    else
      m_rings.clear();

    m_ringsPerceived = true;
  }

  return m_rings;
}

} // end Core namespace
} // end Avogadro namespace
