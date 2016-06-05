/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_CRYSTALTOOLS_H
#define AVOGADRO_CORE_CRYSTALTOOLS_H

#include "array.h"
#include "avogadrocore.h"
#include "matrix.h"
#include "vector.h"

namespace Avogadro {
namespace Core {
class Molecule;
class UnitCell;

/**
 * @class CrystalTools crystaltools.h <avogadro/core/crystaltools.h>
 * @brief The CrystalTools class contains a collection of static functions
 * that perform common crystallographic operations on a Core::Molecule.
 */
class AVOGADROCORE_EXPORT CrystalTools
{
public:
  /**
   * @brief The Option enum provides bitwise option flags for the various
   * algorithms.
   */
  enum Option {
    /** No options specified. */
    None = 0x0,
    /** Transform atoms along with the unit cell. */
    TransformAtoms = 0x1
  };
  typedef int Options;

  /**
   * Adjust the atomic positions in @a molecule so that the fractional (lattice)
   * coordinates of all atoms are in the range [0, 1].
   * @return True on success, false otherwise.
   */
  static bool wrapAtomsToUnitCell(Molecule &molecule);

  /**
   * This function will rotate the input molecule so that the unit cell's 'a'
   * vector is aligned to the x-axis, and the 'b' axis is in the xy-plane. It
   * does not use trig functions or the cell parameters, since such
   * implementations are fragile and cannot handle negative cell angles. The
   * derivation of this algorithm can be found at
   * http://xtalopt.openmolecules.net/misc/rotateToStdOrientation.pdf.
   *
   * @param opts If TransformAtoms is specified, the atoms in @a molecule are
   * rotated along with the unit cell.
   * @return True on success, false otherwise.
   */
  static bool rotateToStandardOrientation(Molecule &molecule,
                                          Options opts = None);

  /**
   * Isotropically scale the volume of the unit cell in @a molecule to @a
   * newVolume (in cubic angstrom).
   * @param opts If TransformAtoms is specified, the atoms in @a molecule are
   * adjusted so that their fractional (lattice) coordinates are preserved.
   * @return True on success, false on failure.
   */
  static bool setVolume(Molecule &molecule, Real newVolume,
                        Options opts = None);

  /**
   * Perform a Niggli reduction on @a molecule's unit cell. This produces a
   * canonical unit cell representation that strives to be as cubic as possible.
   * @note Implements the niggli reduction algorithm detailed in:
   * Grosse-Kunstleve RW, Sauter NK, Adams PD. Numerically stable
   * algorithms for the computation of reduced unit cells. Acta
   * Crystallographica Section A Foundations of
   * Crystallography. 2003;60(1):1-6.
   * @param opts If TransformAtoms is specified, the atom positions are modified
   * to ensure that the same extended atomic structure from the input is
   * represented by the output.
   * @return True on success, false on failure.
   */
  static bool niggliReduce(Molecule &molecule, Options opts = None);

  /**
   * Return true if the unit cell in @a molecule is already Niggli-reduced. This
   * method checks the conditions listed in the paper Gruber B.. Acta Cryst. A.
   * 1973;29(4):433-440.
   */
  static bool isNiggliReduced(const Molecule& mol);

  /**
   * Set the unit cell in @a molecule to represent the real-space column-vector
   * unit cell description in @a newCellColMatrix. A unit cell is created if
   * needed.
   * @param opt If TransformAtoms is specified, the atoms in @a molecule are
   * adjusted so that their fractional (lattice) coordinates are preserved. This
   * option is ignored if the input molecule has no unit cell.
   * @return True on success, false otherwise.
   */
  static bool setCellMatrix(Molecule &molecule, const Matrix3 &newCellColMatrix,
                            Options opt = None);

  /**
   * Populate the @a frac vector with the fractional representation of the
   * cartesian coordinates in @a cart, using @a unitCell to perform the
   * coordinate transformation.
   * @return True on success, false otherwise.
   */
  static bool fractionalCoordinates(const UnitCell &unitCell,
                                    const Array<Vector3> &cart,
                                    Array<Vector3> &frac);

  /**
   * Populate the @a coords vector with the fractional coordinates of the atoms
   * in @a molecule, using the unit cell of @a molecule to perform the
   * coordinate transformation. Coordinates are ordered the same as the
   * Molecule::atomPositions3d() result.
   * @return True on success, false otherwise.
   */
  static bool fractionalCoordinates(const Molecule &molecule,
                                    Array<Vector3> &coords);

  /**
   * Set the atomic positions of @a molecule to the fractional coordinates in
   * @a coords, using the unit cell of @a molecule to perform the coordinate
   * transformation.
   * @return
   */
  static bool setFractionalCoordinates(Molecule &molecule,
                                       const Array<Vector3> &coords);

  /**
   * perceive space group
   * @return
   */
  static bool getSpacegroup(Molecule &molecule);

  /**
   * Set the rotation matrices and translation vectors according the
   * Hall index in Avospg
   * @return
   */
  static bool setSpaceGroup(Molecule &molecule, const int hallNumber);

  /**
   * Fill the unit cell according to the rotation matrices and translation vectors
   * defined by the space group.
   * @return
   */
  static bool fillUnitCell(Molecule &molecule);

  /**
   * Replicate the cell along the a, b and c vectors
   * @return
   */
  static bool buildSuperCell(Molecule &molecule, const unsigned int v1,
                                  const unsigned int v2,
                                  const unsigned int v3);
  static bool buildSlab(Molecule &molecule, std::vector<int> inputIndices, Vector3 cutoff);

  static bool primitiveReduce(Molecule &molecule);
  static bool asymmetricReduce(Molecule &molecule);
  static bool symmetrizeCell(Molecule &molecule);
  static void printFractional(Molecule &molecule);


private:
  CrystalTools(); // not implemented
  ~CrystalTools(); // not implemented
  static int gcdSmall(const int aOriginal, const int bOriginal);
  static bool vectorNormIsLessThan(Vector3 a, Vector3 b);
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_CRYSTALTOOLS_H
