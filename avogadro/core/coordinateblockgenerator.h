/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H
#define AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H

#include <avogadrocoreexport.h>

#include <sstream>
#include <string>

namespace Avogadro {
namespace Core {
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
  CoordinateBlockGenerator();

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
   * Generate and return the coordinate block.
   */
  std::string generateCoordinateBlock();

private:
  const Molecule* m_molecule;
  std::string m_specification;
  DistanceUnit m_distanceUnit;
  std::stringstream m_stream;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_COORDINATEBLOCKGENERATOR_H
