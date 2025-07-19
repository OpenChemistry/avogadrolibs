/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "angleiterator.h"

#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

namespace Avogadro::Core {

AngleIterator::AngleIterator(const Molecule* mol)
  : m_a(MaxIndex), m_b(0), m_c(MaxIndex), m_mol(mol)
{
}

Angle AngleIterator::begin()
{
  return ++(*this);
}

Angle AngleIterator::operator++()
{
  // never any angles
  if (m_mol == nullptr || m_mol->atomCount() < 3 || m_mol->bondCount() < 2)
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex);

  Graph graph = m_mol->graph();
  Index count = m_mol->atomCount();

  // true if we have a valid current state
  // (i.e. false at the start since a == b == c)
  bool valid = (m_a != MaxIndex && m_c != MaxIndex);
  Index aIndex = MaxIndex;
  Index cIndex = MaxIndex;

  // if we don't have a valid state, try to find an initial angle
  if (!valid) {
    for (Index i = 0; i < count; ++i) {
      const auto& neighbors = graph.neighbors(i);
      if (neighbors.size() < 2)
        continue;

      m_b = i;
      m_a = 0;
      m_c = 1;
      aIndex = neighbors[m_a];
      cIndex = neighbors[m_c];
      valid = true;
      break;
    }
  } else {
    // we have a valid state, try to find the next angle
    const auto& neighbors = graph.neighbors(m_b);
    // first check if we can increment m_c
    if (m_c + 1 < neighbors.size()) {
      ++m_c;
      aIndex = neighbors[m_a];
      cIndex = neighbors[m_c];
    } else {
      // we can't increment m_c, try to increment m_a
      if (m_a < neighbors.size() - 2) {
        ++m_a;
        m_c = m_a + 1;
        aIndex = neighbors[m_a];
        cIndex = neighbors[m_c];
      } else {
        // we can't increment m_a, try to increment m_b
        // and reset m_a and m_c
        valid = false;
        for (Index i = m_b + 1; i < count; ++i) {
          const auto& newNeighbors = graph.neighbors(i);
          if (newNeighbors.size() < 2)
            continue;

          m_b = i;
          m_a = 0;
          m_c = 1;
          aIndex = newNeighbors[m_a];
          cIndex = newNeighbors[m_c];
          valid = true;
          break;
        }
      }
    }
  }

  if (valid) {
    m_current = std::make_tuple(aIndex, m_b, cIndex);
  } else // no more valid angles
    m_current = std::make_tuple(MaxIndex, MaxIndex, MaxIndex);

  return m_current;
} // end ++ operator

} // namespace Avogadro::Core
