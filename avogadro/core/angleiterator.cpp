/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "angleiterator.h"

#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

#include <iostream>

namespace Avogadro {
namespace Core {

using namespace std;

AngleIterator::AngleIterator(const Molecule* mol)
  : m_current(0, 0, 0), m_mol(mol)
{}

Angle AngleIterator::begin()
{
  return ++(*this);
}

Angle AngleIterator::operator++()
{
  if (m_mol == nullptr)
    return make_tuple(MaxIndex, MaxIndex, MaxIndex);

  Index a, b, c;
  std::tie(a, b, c) = m_current;

  Graph graph = m_mol->graph();
  Index count = m_mol->atomCount();

  // true if we have a valid current state
  // (i.e. false at the start since a == b == c)
  bool valid = (b != a);

  do {   // vertex
    do { // find good edges

      if (valid) {
        // we have a valid current angle, try to find a new edge
        for (const auto maybeC : graph.neighbors(b)) {
          if (maybeC != a 
            && (!valid || maybeC > c)) {
            m_current = make_tuple(a, b, maybeC);
            return m_current;
          }

        }               // end "c" loop
        valid = false; // we couldn't find a "c", so find a new "a"
      }               // end if()

      // can we find a new edge?
      for (const auto maybeA : graph.neighbors(b)) {
        if (maybeA > a && maybeA != c) {
          a = maybeA;
          c = a;
          valid = true;
          break;
        }
      } // end "a" loop

      // if we don't have a valid "a", move out to find a new "b"
    } while (valid);

    while(!valid && b + 1 < count) {
      ++b; // try going to the next atom

      const auto neighbors = graph.neighbors(b);
      if (neighbors.size() < 2)
        continue;
      
      a = neighbors[0];
      c = neighbors[0]; // we'll move to the next one in the loop
      valid = true;
    }
  } while (valid && b < count);

  // can't find anything
  return make_tuple(MaxIndex, MaxIndex, MaxIndex);
} // end ++ operator

} // namespace Core
} // namespace Avogadro
