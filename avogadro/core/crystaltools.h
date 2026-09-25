/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CRYSTALTOOLS_H
#define AVOGADRO_CORE_CRYSTALTOOLS_H

#include "avogadrocoreexport.h"

#include "array.h"
#include "avogadrocore.h"
#include "matrix.h"
#include "vector.h"

namespace Avogadro::Core {
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
  enum Option
  {
    /** No options specified. */
    None = 0x0,
    /** Transform atoms along with the unit cell. */
    TransformAtoms = 0x1,
    /** Enforce right-handed system */
    RightHanded = 0x2,
    /** Bond the replicated cells to each other across periodic boundaries. */
    PerceivePeriodicBonds = 0x4
  };
  using Options = int;

  /**
   * Adjust the atomic positions in @a molecule so that the fractional (lattice)
   * coordinates of all atoms are in the range [0, 1].
   * @return True on success, false otherwise.
   */
  static bool wrapAtomsToUnitCell(Molecule& molecule);

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
  static bool rotateToStandardOrientation(Molecule& molecule,
                                          Options opts = None);

  /**
   * Isotropically scale the volume of the unit cell in @a molecule to @a
   * newVolume (in cubic angstrom).
   * @param opts If TransformAtoms is specified, the atoms in @a molecule are
   * adjusted so that their fractional (lattice) coordinates are preserved.
   * @return True on success, false on failure.
   */
  static bool setVolume(Molecule& molecule, Real newVolume,
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
  static bool niggliReduce(Molecule& molecule, Options opts = None);

  /**
   * Return true if the unit cell in @a molecule is already Niggli-reduced. This
   * method checks the conditions listed in the paper Gruber B.. Acta Cryst. A.
   * 1973;29(4):433-440.
   */
  static bool isNiggliReduced(const Molecule& mol);

  /**
   * @brief A single bond of a periodic structure.
   *
   * The bond joins @a atom1 to the image of @a atom2 displaced by @a offset
   * lattice vectors, so a zero @a offset is an ordinary bond lying wholly
   * inside the cell and anything else crosses a cell boundary.
   */
  struct PeriodicBond
  {
    /** Index of the first atom. */
    Index atom1;
    /** Index of the second atom. */
    Index atom2;
    /** Lattice translation applied to @a atom2, in whole cell units. */
    Vector3i offset;
    /** Bond order. Newly perceived bonds are always single. */
    unsigned char order;
    /** True if this pass found the bond, false if @a molecule already had it.
     */
    bool perceived;
  };

  /**
   * Work out the full bond topology of a periodic structure, including the
   * bonds that cross a cell boundary and are therefore missing from the
   * molecule itself: once the atoms have been wrapped into the cell their
   * periodic neighbours sit a whole cell away in Cartesian space, so ordinary
   * distance-based perception never sees them.
   *
   * The molecule's own bonds come first in the returned list, in molecule bond
   * order, followed by any that this pass perceived.
   *
   * Every bond already in @a molecule comes back with its order intact and with
   * the lattice offset of whichever image of the second atom lies nearest the
   * first, so a bond stored stretched across the cell is reported as the short
   * bond it really is. Further bonds are perceived only where they cross a cell
   * boundary, using covalent radii plus @a tolerance. Pairs lying wholly inside
   * the cell are left to the molecule's own connectivity, so this never
   * second-guesses the bonding that a file specified.
   *
   * If @a molecule has no unit cell, or has no coordinates, its bonds are
   * returned unchanged with zero offsets.
   *
   * @param tolerance Added to the sum of the two covalent radii.
   */
  static Array<PeriodicBond> perceivePeriodicBonds(const Molecule& molecule,
                                                   double tolerance = 0.45);

  /**
   * Build a supercell by expanding upon the unit cell of @a molecule. It will
   * only return false if the molecule does not have a unit cell or if a, b, or
   * c is set to zero.
   * @param a The number of units along lattice vector a for the supercell
   * @param b The number of units along lattice vector b for the supercell
   * @param c The number of units along lattice vector c for the supercell
   * @param opts If PerceivePeriodicBonds is specified, the copies are bonded to
   * each other across the cell boundaries they share.
   * @return True on success, false on failure.
   */
  static bool buildSupercell(Molecule& molecule, unsigned int a, unsigned int b,
                             unsigned int c, Options opts = None);

  /**
   * Build a supercell by replicating the unit cell of @a molecule over a
   * fractional range along each lattice vector, e.g. -0.5 to 0.5, or 0.0 to
   * 1.5.
   *
   * If every limit is an integer the result is a true supercell: the range is
   * treated as half-open, the cell vectors are scaled by (max - min), and the
   * atoms are shifted so that @a rangeMin lands on the new origin. Passing
   * (0, 0, 0) and (a, b, c) is therefore identical to the integer form above.
   *
   * A non-integer limit cannot describe a lattice, so in that case the unit
   * cell is left untouched and the replicated atoms simply extend beyond it -
   * the usual crystal packing view. The range is then treated as closed, so
   * atoms lying on either bounding face are included.
   *
   * @param rangeMin The lower fractional limit along a, b and c.
   * @param rangeMax The upper fractional limit along a, b and c.
   * @param opts If PerceivePeriodicBonds is specified, the copies are bonded to
   * each other across the cell boundaries they share, so that a molecule split
   * by a boundary is drawn whole wherever both of its halves are present.
   * @return True on success, false if @a molecule has no unit cell or if any
   * axis has an empty range (max <= min).
   */
  static bool buildSupercell(Molecule& molecule, const Vector3& rangeMin,
                             const Vector3& rangeMax, Options opts = None);

  /**
   * Set the unit cell in @a molecule to represent the real-space column-vector
   * unit cell description in @a newCellColMatrix. A unit cell is created if
   * needed.
   * @param opt If TransformAtoms is specified, the atoms in @a molecule are
   * adjusted so that their fractional (lattice) coordinates are preserved. This
   * option is ignored if the input molecule has no unit cell.
   * @return True on success, false otherwise.
   */
  static bool setCellMatrix(Molecule& molecule, const Matrix3& newCellColMatrix,
                            Options opt = None);

  /**
   * Populate the @a frac vector with the fractional representation of the
   * cartesian coordinates in @a cart, using @a unitCell to perform the
   * coordinate transformation.
   * @return True on success, false otherwise.
   */
  static bool fractionalCoordinates(const UnitCell& unitCell,
                                    const Array<Vector3>& cart,
                                    Array<Vector3>& frac);

  /**
   * Populate the @a coords vector with the fractional coordinates of the atoms
   * in @a molecule, using the unit cell of @a molecule to perform the
   * coordinate transformation. Coordinates are ordered the same as the
   * Molecule::atomPositions3d() result.
   * @return True on success, false otherwise.
   */
  static bool fractionalCoordinates(const Molecule& molecule,
                                    Array<Vector3>& coords);

  /**
   * Set the atomic positions of @a molecule to the fractional coordinates in
   * @a coords, using the unit cell of @a molecule to perform the coordinate
   * transformation.
   */
  static bool setFractionalCoordinates(Molecule& molecule,
                                       const Array<Vector3>& coords);

private:
  CrystalTools();  // not implemented
  ~CrystalTools(); // not implemented
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_CRYSTALTOOLS_H
