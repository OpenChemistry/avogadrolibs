/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SECONDARYSTRUCTURE_H
#define AVOGADRO_CORE_SECONDARYSTRUCTURE_H

#include "avogadrocore.h"

#include <tuple>
#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;

//! \internal
struct hBondRecord
{
  //! The atom index we're examining
  Index atom;
  //! The z-coordinate of the atom
  float atomZ;
  //! The residue containing the atom
  Index residue;
  //! The residue we're paired through an hbond
  Index residuePair;
  //! The length (squared) of the hydrogen bond
  float distSquared;
};

void assignSecondaryStructure(Molecule* mol);

//! \internal
std::vector<hBondRecord> assignBackboneHydrogenBonds(Molecule *mol);

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLEITERATOR_H
