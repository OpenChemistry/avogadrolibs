/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_MOLECULESNAPSHOT_H
#define AVOGADRO_CORE_MOLECULESNAPSHOT_H

#include "avogadrocoreexport.h"

#include "atomstate.h"
#include "avogadrocore.h"
#include "bondstate.h"
#include "constraint.h"
#include "propertymap.h"
#include "residue.h"
#include "vector.h"

#include <string>
#include <utility>
#include <vector>

namespace Avogadro::Core {

class Molecule;

/**
 * @class BondSnapshot moleculesnapshot.h <avogadro/core/moleculesnapshot.h>
 * @brief What Molecule::removeBond() discards, saved so that
 * Molecule::restoreBondSnapshot() can put it back.
 *
 * A snapshot is opaque: it is only meaningful when restored into the molecule
 * it was taken from, in exactly the state the removal left it. It holds no
 * calculated results (partial charges are discarded and stay discarded).
 */
class AVOGADROCORE_EXPORT BondSnapshot
{
public:
  BondSnapshot() = default;

  /** @return true if this snapshot holds nothing (it was default-constructed
   * or Molecule::bondSnapshot() refused). */
  bool isEmpty() const { return m_count == 0; }

private:
  friend class Molecule;

  Index m_id = 0; //!< the bond's index, for the bonds inside an AtomSnapshot
  std::pair<Index, Index> m_pair{ MaxIndex, MaxIndex };
  BondState m_state;
  Index m_count = 0; //!< bondCount() when the snapshot was taken
};

/**
 * @class AtomSnapshot moleculesnapshot.h <avogadro/core/moleculesnapshot.h>
 * @brief What Molecule::removeAtom() discards, saved so that
 * Molecule::restoreAtomSnapshot() can put it back.
 *
 * A snapshot is opaque: it is only meaningful when restored into the molecule
 * it was taken from, in exactly the state the removal left it. It holds the
 * atom's element, layer, per-atom state, 3D position in every coordinate
 * frame, the constraints and scan coordinates and residues the removal
 * drops, and the bonds the removal takes with it. It holds no calculated
 * results (partial charges, forces, velocities, vibrations, spectra), which
 * a removal discards and a restoration does not bring back.
 *
 * @note The position in every frame costs about 32 bytes per frame per atom
 * (24 for the position, plus a flag and padding). An undo history that limits
 * its memory has to count that.
 */
class AVOGADROCORE_EXPORT AtomSnapshot
{
public:
  AtomSnapshot() = default;

  /** @return true if this snapshot holds nothing (it was default-constructed
   * or Molecule::atomSnapshot() refused). */
  bool isEmpty() const { return m_count == 0; }

  /** @return true if the removal this snapshot was taken for also removes
   * bonds, which restoring brings back. */
  bool hasBonds() const { return !m_bonds.empty(); }

private:
  friend class Molecule;

  // The atom's entry in one position array, and how the removal treated the
  // array: left alone (it did not reach the atom), entry overwritten (shorter
  // than the atom count), or swap-and-popped (covered every atom). Unlike
  // Column::slice(), the last atom's value is not saved: the swap-and-pop
  // moved it into the atom's index, where the restoration finds it.
  enum class PositionRemoval : unsigned char
  {
    None,
    Overwritten,
    SwapAndPop
  };
  struct PositionSlice
  {
    Vector3 value = Vector3::Zero();
    PositionRemoval removal = PositionRemoval::None;
  };

  struct DroppedResidue
  {
    Index index = 0;
    Residue residue;
    std::string label;
    PropertyMap properties;
  };

  struct DroppedConstraint
  {
    size_t position = 0; //!< index in the vector it was dropped from
    Constraint constraint;
  };

  Index m_count = 0; //!< atomCount() when the snapshot was taken
  unsigned char m_atomicNumber = 0;
  AtomState m_state;
  PositionSlice m_position;
  std::vector<PositionSlice> m_framePositions;

  // The layer array may be shorter than the atom count, and removal
  // swap-and-pops within its own length.
  Index m_layerCount = 0;
  size_t m_layer = 0;
  size_t m_lastLayer = 0;

  std::vector<DroppedConstraint> m_constraints;
  std::vector<DroppedConstraint> m_scanCoordinates;
  std::vector<DroppedResidue> m_residues; //!< in the order they were removed
  std::vector<BondSnapshot> m_bonds;      //!< in the order they were removed
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_MOLECULESNAPSHOT_H
