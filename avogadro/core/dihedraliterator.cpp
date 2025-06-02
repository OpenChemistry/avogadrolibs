/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dihedraliterator.h"

#include <avogadro/core/graph.h>
#include <avogadro/core/molecule.h>

namespace Avogadro::Core {

DihedralIterator::DihedralIterator(const Molecule* mol)
  : m_i(MaxIndex), m_jk(0), m_l(MaxIndex), m_mol(mol)
{
  m_current = std::make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
}

Dihedral DihedralIterator::begin()
{
  // all the logic is in the operator++
  return ++(*this);
}

Dihedral DihedralIterator::operator++()
{
  // impossible to have a dihedral, so quit
  if (m_mol == nullptr || m_mol->atomCount() < 4 || m_mol->bondCount() < 3)
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);

  Graph graph = m_mol->graph();
  Index count = m_mol->bondCount();

  // true if we have a valid current state
  // (i.e. false at the start)
  bool valid = (m_i != MaxIndex && m_l != MaxIndex);

  // m_jk is the current bond (i.e. index into the bonds)
  // m_i and m_l are instead index into the neighbors of m_jk
  // (i.e., m_i is the index into the neighbors of the first atom of the bond)
  // and m_l is the index into the neighbors of the second atom of the bond
  Index iIndex = MaxIndex;
  Index lIndex = MaxIndex;

  // if we don't have a valid state, try to find an initial dihedral
  if (!valid) {
    for (Index i = 0; i < count; ++i) {
      const Bond bond = m_mol->bond(i);
      const auto& neighbors1 = graph.neighbors(bond.atom1().index());
      const auto& neighbors2 = graph.neighbors(bond.atom2().index());

      if (neighbors1.size() < 1 || neighbors2.size() < 1)
        continue; // need to have at least one neighbor

      m_jk = i;
      // make sure that m_i doesn't point to atom2
      m_i = 0;
      if (neighbors1[m_i] == bond.atom2().index()) {
        // try to increment m_i
        if (m_i + 1 < neighbors1.size()) {
          ++m_i;
        } else {
          continue; // this central bond doesn't work
        }
      }

      m_l = 0;
      // make sure that m_l doesn't point to atom1
      if (neighbors2[m_l] == bond.atom1().index()) {
        // try to increment m_l
        if (m_l + 1 < neighbors2.size()) {
          ++m_l;
        } else {
          continue; // this central bond doesn't work
        }
      }

      iIndex = neighbors1[m_i];
      lIndex = neighbors2[m_l];

      valid = true;
      break;
    }
  } else {
    // we have a valid state, try to find the next dihedral
    const Bond bond = m_mol->bond(m_jk);
    const auto& neighbors1 = graph.neighbors(bond.atom1().index());
    const auto& neighbors2 = graph.neighbors(bond.atom2().index());

    // first check if we can increment m_l
    while (m_l + 1 < neighbors2.size()) {
      ++m_l;

      // make sure that m_l doesn't point to atom1
      if (neighbors2[m_l] == bond.atom1().index()) {
        continue; // increment it again
      }

      iIndex = neighbors1[m_i];
      lIndex = neighbors2[m_l];
      m_current = std::make_tuple(iIndex, bond.atom1().index(),
                                  bond.atom2().index(), lIndex);
      return m_current;
    }

    // we can try to increment m_i
    while (m_i + 1 < neighbors1.size()) {
      ++m_i;
      // make sure that m_i doesn't point to atom2
      if (neighbors1[m_i] == bond.atom2().index()) {
        // try to increment m_i again
        continue;
      }

      // reset m_l and make sure it doesn't point to atom1
      m_l = 0;
      if (neighbors2[m_l] == bond.atom1().index()) {
        // try to increment m_l
        if (m_l + 1 < neighbors2.size()) {
          ++m_l;
        } else {
          continue; // this combination doesn't work
        }
      }

      iIndex = neighbors1[m_i];
      lIndex = neighbors2[m_l];
      m_current = std::make_tuple(iIndex, bond.atom1().index(),
                                  bond.atom2().index(), lIndex);
      return m_current;
    }

    // okay, try to increment m_jk and reset m_i and m_l
    valid = false;
    for (Index i = m_jk + 1; i < count; ++i) {
      const Bond bondI = m_mol->bond(i);

      const auto& newNeighbors1 = graph.neighbors(bondI.atom1().index());
      const auto& newNeighbors2 = graph.neighbors(bondI.atom2().index());

      if (newNeighbors1.size() < 1 || newNeighbors2.size() < 1)
        continue; // need to have at least one neighbor

      m_jk = i;
      // make sure that m_i doesn't point to atom2
      m_i = 0;
      if (newNeighbors1[m_i] == bondI.atom2().index()) {
        // try to increment m_i
        if (m_i + 1 < newNeighbors1.size()) {
          ++m_i;
        } else {
          continue; // this central bond doesn't work
        }
      }

      m_l = 0;
      // make sure that m_l doesn't point to atom1
      if (newNeighbors2[m_l] == bondI.atom1().index()) {
        // try to increment m_l
        if (m_l + 1 < newNeighbors2.size()) {
          ++m_l;
        } else {
          continue; // this central bond doesn't work
        }
      }

      iIndex = newNeighbors1[m_i];
      lIndex = newNeighbors2[m_l];

      valid = true;
      break;
    }
  }

  // did we find anything?
  if (valid) {
    const Bond bond = m_mol->bond(m_jk);
    m_current = std::make_tuple(iIndex, bond.atom1().index(),
                                bond.atom2().index(), lIndex);
    return m_current;
  } else
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
} // end ++ operator

} // namespace Avogadro::Core
