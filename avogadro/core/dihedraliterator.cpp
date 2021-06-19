/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dihedraliterator.h"

#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

#include <iostream>

namespace Avogadro {
namespace Core {

using namespace std;

DihedralIterator::DihedralIterator(const Molecule* mol)
  : m_current(0, 0, 0, 0), m_mol(mol)
{}

Dihedral DihedralIterator::begin()
{
  if (m_mol == nullptr)
    return make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);

  // Loop through bonds until we get one with a-b-c-d
  Graph graph = m_mol->graph();
  Index bondCount = m_mol->bondCount();
  if (bondCount > 3) {
    // need at least a-b-c-d to have a dihedral
    bool valid = false;
    for (Index bcBond = 0; bcBond < bondCount; ++bcBond) {
      auto bc = m_mol->bondPair(bcBond);
      Index b = bc.first;
      Index c = bc.second;

      // find an a
      Index a, d;
      for (const auto maybeA : graph.neighbors(b)) {
        if (maybeA != c) {
          a = maybeA;
          valid = true; // maybe
          break;
        }
      }
      if (!valid)
        continue; // need to find a new bond with real neighbors

      // try to find a new d
      for (const auto maybeD : graph.neighbors(c)) {
        if (maybeD != b && maybeD != a) {
          m_current = make_tuple(a, b, c, maybeD);
          return m_current; // done
        }
      }
      // didn't find a good "d", so try a new bond
      valid = false;
    }
  }

  // we couldn't find a valid dihedral (e.g., small molecule, single atom)
  return make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
}

Dihedral DihedralIterator::operator++()
{
  if (m_mol == nullptr)
    return make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);

  Index a, b, c, d;
  std::tie(a, b, c, d) = m_current;

  Graph graph = m_mol->graph();
  Index count = m_mol->atomCount();

  // we start at a good state (i.e., we have a valid dihedral)
  bool valid = (b != c && b != MaxIndex);
  Index bondCount = m_mol->bondCount();
  Index bcBond = 0;

  do { // b-c bond

    if (valid) {
      // we have a valid current dihedral, try to find a new "d"
      for (const auto maybeD : graph.neighbors(c)) {
        if (maybeD != a && maybeD != b && (!valid || maybeD > d)) {
          m_current = make_tuple(a, b, c, maybeD);
          return m_current;
        }

      }              // end "d" loop
      valid = false; // we couldn't find a "d", so find a new "a"
    }                // end if()

    // try to find a new "a"
    for (const auto maybeA : graph.neighbors(b)) {
      if (maybeA != c && maybeA > a) {
        a = maybeA;
        d = 0;
        valid = true; // maybe
        break;
      }
    }

    // find our current bond and go to the next
    if (!valid) {
    bool nextBond = false;
    for (bcBond = 0; bcBond < bondCount; ++bcBond) {
      auto bc = m_mol->bondPair(bcBond);
      Index maybeB = bc.first;
      Index maybeC = bc.second;

      if (nextBond) {
        b = maybeB;
        c = maybeC;

        // find an a
        Index a, d;
        for (const auto maybeA : graph.neighbors(b)) {
          if (maybeA != c) {
            a = maybeA;
            valid = true; // maybe
            break;
          }
        }
        if (!valid) {
          continue; // need to find a new bond with real neighbors
        }

        // try to find a new d
        for (const auto maybeD : graph.neighbors(c)) {
          if (maybeD != b && maybeD != a) {
            m_current = make_tuple(a, b, c, maybeD);
            return m_current; // done
          }
        }
        // didn't find a good "d", so try a new bond
        break;
      }

      if (!nextBond && maybeB == b && maybeC == c) {
        // found current bond
        nextBond = true;
      }
    }

    valid = nextBond;
    }
  } while (valid && bcBond < bondCount);

  // can't find anything
  return make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
} // end ++ operator

} // namespace Core
} // namespace Avogadro
