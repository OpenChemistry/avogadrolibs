/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SECONDARYSTRUCTURE_H
#define AVOGADRO_CORE_SECONDARYSTRUCTURE_H

#include "avogadrocoreexport.h"

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

class AVOGADROCORE_EXPORT SecondaryStructureAssigner
{
public:
  // construction and destruction
  explicit SecondaryStructureAssigner(Molecule* m = nullptr);
  ~SecondaryStructureAssigner();

  void assign(Molecule* mol);

private:
  void assignBackboneHydrogenBonds();

  Molecule* m_molecule;
  std::vector<hBondRecord*> m_hBonds;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLEITERATOR_H
