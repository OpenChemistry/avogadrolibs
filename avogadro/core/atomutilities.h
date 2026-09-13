/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_ATOMUTILITIES_H
#define AVOGADRO_QTGUI_ATOMUTILITIES_H

#include "avogadrocoreexport.h"

#include <avogadro/core/molecule.h>

#include <vector>

namespace Avogadro::Core {
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
  static Vector3 generateNewBondVector(
    const Atom& atom, const std::vector<Vector3>& currentVectors,
    AtomHybridization hybridization);

  /**
   * @return the ideal length in Angstroms of a bond of order @a bondOrder
   * between elements @a atomicNumber1 and @a atomicNumber2.
   *
   * The default is the sum of the Pyykko covalent radii, scaled down for
   * double and triple bonds. That estimate is within a few percent for most
   * element pairs, but it is systematically wrong for strongly polar bonds
   * (Si-F, B-F, P-O) and for bonds between lone-pair rich atoms (O-O, F-F),
   * so a table of measured lengths overrides it for common bonds.
   *
   * Intended for building and editing geometries, not for structure
   * validation: the returned value is a single representative length and
   * ignores hybridization, formal charge, and neighboring substituents.
   */
  static Real idealBondLength(unsigned char atomicNumber1,
                              unsigned char atomicNumber2,
                              unsigned char bondOrder = 1);

private:
  AtomUtilities();  // Not implemented
  ~AtomUtilities(); // Not implemented
};

} // namespace Avogadro::Core

#endif // AVOGADRO_QTGUI_ATOMUTILITIES_H
