/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ATOMUTILITIES_H
#define AVOGADRO_QTGUI_ATOMUTILITIES_H

#include "avogadrocoreexport.h"

#include "avogadrocoreexport.h"

#include <avogadro/core/molecule.h>

#include <vector>

namespace Avogadro {
namespace Core {
class Atom;
class Molecule;

class AVOGADROCORE_EXPORT AtomUtilities
{
public:
  /**
   * Perceive the geometry / hybridization bonded to @a atom.
   * Ideally, the client should cache the hybridization number
   * by calling setHybridization() later
   */
  static AtomHybridization perceiveHybridization(const Atom& atom);

  /**
   * Generate a new bond vector (unit length)
   */
  static Vector3 generateNewBondVector(const Atom& atom,
                                       const std::vector<Vector3>& currentVectors,
                                       AtomHybridization hybridization);

private:
  AtomUtilities();  // Not implemented
  ~AtomUtilities(); // Not implemented
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_ATOMUTILITIES_H
