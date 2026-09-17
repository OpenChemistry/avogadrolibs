/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H
#define AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H

#include "avogadrocoreexport.h"

#include "array.h"
#include "avogadrocore.h"

#include <sstream>
#include <string>

namespace Avogadro::Core {
class Molecule;

/**
 * @class CoordinateBlockGenerator coordinateblockgenerator.h
 * <avogadro/core/coordinateblockgenerator.h>
 * @brief The CoordinateBlockGenerator class creates an aligned, formatted block
 * of atomic coordinates.
 *
 * See the setSpecification() documentation for details on specifying the block
 * format.
 */
class AVOGADROCORE_EXPORT CoordinateBlockGenerator
{
public:
  /**
   * Construct the default CoordinateBlockGenerator with an empty specification
   * and Angstrom distance units.
   */
  CoordinateBlockGenerator() = default;

  /**
   * The molecule used as input.
   * @}
   */
  void setMolecule(const Molecule* mol) { m_molecule = mol; }
  const Molecule* molecule() const { return m_molecule; }
  /** @} */

  /**
   * The specification of the block format.
   * The characters in the specification string indicate the information needed
   * about each atom in the coordinate block.
   * - @c #: Atom index (one-based index)
   * - @c Z: Atomic number (e.g. "6" for carbon)
   * - @c L: Atomic label (e.g., "C1" for first carbon)")
   * - @c G: GAMESS-styled Atomic number (e.g. "6.0" for carbon)
   * - @c S: Element symbol (e.g. "C" for carbon)
   * - @c N: Element name (e.g. "Carbon")
   * - @c x: X cartesian coordinate
   * - @c y: Y cartesian coordinate
   * - @c z: Z cartesian coordinate
   * - @c a: 'a' lattice coordinate (unit cell required)
   * - @c b: 'b' lattice coordinate (unit cell required)
   * - @c c: 'c' lattice coordinate (unit cell required)
   * - @c 0: A literal "0". Useful for optimization flags.
   * - @c 1: A literal "1". Useful for optimization flags.
   * - @c _: A space character. Useful for alignment.
   * - @c ,: A literal comma, with no space added on either side of it.
   *   Useful for comma-delimited formats such as Molpro.
   *
   * In the z-matrix modes (see setMode()) a row describes one atom in terms
   * of three earlier ones, and six further characters are recognized:
   * - @c I: Index of the distance reference atom's row
   * - @c J: Index of the angle reference atom's row
   * - @c K: Index of the dihedral reference atom's row
   * - @c R: Distance to the @c I atom
   * - @c A: Angle at the @c I atom to the @c J atom, in degrees
   * - @c T: Dihedral about the @c I - @c J axis to the @c K atom, in degrees
   *
   * All of these are one-based, and they number z-matrix @em rows rather
   * than molecule atoms. The two agree unless the z-matrix had to be
   * reordered, which atomsReordered() reports. @c # likewise gives the row
   * number in these modes, so that it lines up with @c I, @c J and @c K.
   *
   * For example, the specification string
~~~
__SZxyz110
~~~
   * will be replaced by a molecule-specific block of text similar to the
   * following:
~~~
  C  6    1.126214  0.765886  0.000000 1 1 0
  C  6    0.819345 -0.564955  0.000000 1 1 0
  C  6   -0.598383 -0.795127  0.000000 1 1 0
  C  6   -1.310706  0.370165  0.000000 1 1 0
  S  16  -0.285330  1.757144  0.000000 1 1 0
  H  1    2.130424  1.185837  0.000000 1 1 0
  H  1    1.548377 -1.375303  0.000000 1 1 0
  H  1   -1.033768 -1.794407  0.000000 1 1 0
  H  1   -2.396173  0.450760  0.000000 1 1 0
~~~
   */
  void setSpecification(const std::string& spec) { m_specification = spec; }
  std::string specification() const { return m_specification; }
  /** @} */

  /** Distance unit used in the output. @{ */
  enum DistanceUnit
  {
    Angstrom = 0,
    Bohr
  };
  void setDistanceUnit(DistanceUnit unit) { m_distanceUnit = unit; }
  DistanceUnit distanceUnit() const { return m_distanceUnit; }
  /** @} */

  /**
   * The kind of block produced.
   */
  enum class Mode
  {
    /** One line of Cartesian or lattice coordinates per atom. */
    Cartesian,
    /**
     * A z-matrix, with the missing fields of the opening rows left out
     * entirely along with the space that would have preceded them. This is
     * the form Gaussian, NWChem, Q-Chem, Psi4, Molpro and CFOUR read.
     */
    ZMatrix,
    /**
     * A z-matrix whose opening rows are padded out with zeros, so that every
     * row carries every field. This is the form ORCA's @c int, MOPAC and
     * SIESTA read.
     */
    ZMatrixPadded
  };
  void setMode(Mode mode) { m_mode = mode; }
  Mode mode() const { return m_mode; }
  /** @} */

  /**
   * Generate and return the coordinate block.
   */
  std::string generateCoordinateBlock();

  /**
   * Whether the last z-matrix generated put the atoms in an order other than
   * the molecule's own, so that the row numbers in the block do not match
   * the atom numbering the user sees.
   *
   * A z-matrix has to describe each atom against atoms already placed, which
   * a molecule's atom order does not always allow. Always false after a
   * Cartesian block, whose atoms are always in molecule order.
   */
  bool atomsReordered() const { return m_atomsReordered; }

  /**
   * The rows of the last z-matrix generated whose angle or dihedral is
   * measured against three atoms too close to a straight line for the value
   * to be meaningful.
   *
   * The geometry is still described correctly, but such a coordinate cannot
   * be read or edited sensibly, and a program rebuilding Cartesians from it
   * may not reproduce the molecule exactly. Row numbers are zero-based, as
   * indices into the block's lines; add one to match the @c # field.
   */
  Array<Index> linearRows() const { return m_linearRows; }

private:
  std::string generateZMatrixBlock();

  const Molecule* m_molecule = nullptr;
  std::string m_specification;
  DistanceUnit m_distanceUnit = Angstrom;
  Mode m_mode = Mode::Cartesian;
  bool m_atomsReordered = false;
  Array<Index> m_linearRows;
  std::stringstream m_stream;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H
