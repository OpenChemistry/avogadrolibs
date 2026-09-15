/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CONFORMERQUANTITY_H
#define AVOGADRO_CORE_CONFORMERQUANTITY_H

#include "avogadrocoreexport.h"

#include <avogadro/core/constraint.h>

#include <string>
#include <vector>

namespace Avogadro::Core {

class Molecule;

/**
 * @class ConformerQuantity conformerquantity.h
 * <avogadro/core/conformerquantity.h>
 * @brief Something that can be measured once per coordinate set.
 *
 * A molecule holding several coordinate sets -- conformers, the steps of a
 * relaxed scan, the frames of a dynamics run -- can be asked for any number of
 * quantities that take one value per set: its energy, how far it has moved,
 * how hot it is, or the bond length someone is scanning. This names one of
 * them, and the free functions below enumerate and evaluate them, so that a
 * plot and a table put the same list in front of the user.
 *
 * The values are unit-bearing but carry no unit conversion of their own; see
 * unit() for what each one is measured in.
 */
class AVOGADROCORE_EXPORT ConformerQuantity
{
public:
  enum class Type
  {
    /** The position of the coordinate set in the trajectory, counting at 0. */
    Frame,
    /** Elapsed time, in picoseconds. See frameInterval(). */
    Time,
    /** Root mean square displacement from the first set, in Angstrom. */
    Rmsd,
    /** Energy relative to the lowest set, in the file's own units. */
    Energy,
    /** RMS gradient, in the file's own units. */
    Forces,
    /** Mean atomic speed, in Angstrom per picosecond. */
    MeanSpeed,
    /** Instantaneous temperature, in Kelvin. */
    Temperature,
    /** A distance, angle or torsion followed across the sets. */
    Coordinate
  };

  ConformerQuantity() = default;
  explicit ConformerQuantity(Type quantityType) : m_type(quantityType) {}
  explicit ConformerQuantity(const Constraint& coordinate)
    : m_type(Type::Coordinate), m_coordinate(coordinate)
  {
  }

  Type type() const { return m_type; }

  /**
   * @return the coordinate this quantity measures. Only meaningful for a
   * Coordinate quantity; the default-constructed Constraint returned
   * otherwise measures nothing and reports itself invalid.
   */
  const Constraint& coordinate() const { return m_coordinate; }

  /**
   * @return a name for this quantity that survives the list being rebuilt.
   *
   * The quantities available change as constraints are added and atoms are
   * deleted, so a position in the list is no way to remember which one the
   * user was looking at. A coordinate is named by the atoms it measures,
   * everything else by its type; the two cannot collide, since only a
   * coordinate carries a separator.
   */
  std::string identifier() const;

  /**
   * @return the unit the values are measured in ("Å", "ps", "K"), or an empty
   * string for a quantity that is dimensionless (Frame) or whose unit comes
   * from the file rather than from here (Energy, Forces).
   *
   * For an Energy quantity, ask energyUnit() of the molecule instead: a
   * reader that knows what its program writes records it there.
   *
   * Not translated: these are symbols, and the same in every locale.
   */
  std::string unit() const;

  bool operator==(const ConformerQuantity& other) const
  {
    return m_type == other.m_type &&
           (m_type != Type::Coordinate ||
            m_coordinate.atoms() == other.m_coordinate.atoms());
  }
  bool operator!=(const ConformerQuantity& other) const
  {
    return !(*this == other);
  }

private:
  Type m_type = Type::Frame;
  // Constraint has no default state of its own, so a quantity that measures no
  // coordinate holds one naming no atoms, which reports itself invalid.
  Constraint m_coordinate{ MaxIndex, MaxIndex };
};

/**
 * @return every quantity @p molecule can supply a value for, in a stable
 * order: the built-in ones first, then one per coordinate being followed.
 *
 * A quantity is listed when the molecule either holds the data or can work it
 * out -- speed and temperature are differenced from the trajectory, so they
 * are on offer for any molecule with more than one coordinate set, whether or
 * not estimateVelocities() has been called yet.
 */
AVOGADROCORE_EXPORT std::vector<ConformerQuantity> conformerQuantities(
  const Molecule& molecule);

/**
 * @return one value of @p quantity per coordinate set, in order from the
 * first, or an empty vector when @p molecule holds nothing to measure.
 *
 * A value's position in the result is its coordinate set index, so a molecule
 * carrying fewer energies than geometries still lines up.
 *
 * This only reads the molecule. MeanSpeed and Temperature come from the
 * properties estimateVelocities() fills in, so call that first -- with the
 * interval from frameInterval() -- if the velocities may be stale.
 */
AVOGADROCORE_EXPORT std::vector<double> evaluateConformerQuantity(
  const Molecule& molecule, const ConformerQuantity& quantity);

/**
 * @return the spread of what @p quantity averaged over, one value per
 * coordinate set, or an empty vector for a quantity that is not an average.
 *
 * Only MeanSpeed has one: the standard deviation of the atomic speeds, which
 * says whether a molecule is uniformly warm or has one atom doing all the
 * moving.
 */
AVOGADROCORE_EXPORT std::vector<double> conformerQuantitySpread(
  const Molecule& molecule, const ConformerQuantity& quantity);

/**
 * @return the unit @p molecule's energies are stored in, as the symbol the
 * program that wrote them uses ("Hartree", "kcal/mol", "kJ/mol", "eV"), or an
 * empty string when nothing recorded it.
 *
 * Almost no file says what unit its energies are in, so this is only set by
 * readers that know what the program they are reading always writes -- or, as
 * with QCSchema, by one of the few formats that says so itself. Where it is
 * empty the user has to be asked.
 *
 * Kept in the molecule's property map under "energyUnit", so it survives a
 * round trip through CJSON with everything else there.
 */
AVOGADROCORE_EXPORT std::string energyUnit(const Molecule& molecule);

/**
 * Record the unit @p molecule's energies are stored in.
 *
 * This is what the values actually are, which is not always what the file
 * said: a reader that converts on the way in should record what it converted
 * to. An empty @p unit means it is not known, which is not the same as it
 * being the default.
 */
AVOGADROCORE_EXPORT void setEnergyUnit(Molecule& molecule,
                                       const std::string& unit);

/**
 * @return the interval between @p molecule's coordinate sets, in picoseconds.
 *
 * Kept in the molecule's property map under "frameInterval" so that
 * everything measuring the trajectory against time agrees about it. Falls
 * back to the spacing of the stored timesteps, and then to 1 ps -- few
 * trajectory formats record when their frames were written, so this is
 * usually the user's to set.
 */
AVOGADROCORE_EXPORT double frameInterval(const Molecule& molecule);

/** Set the interval returned by frameInterval(), in picoseconds. */
AVOGADROCORE_EXPORT void setFrameInterval(Molecule& molecule, double interval);

/**
 * Make sure the properties MeanSpeed and Temperature read from are there and
 * current, differencing the trajectory at frameInterval() when the molecule
 * carries no velocities of its own.
 *
 * Cheap to call repeatedly: the work is redone only when the trajectory or
 * the frame interval has changed since the last time, or when @p force says
 * the geometry moved under it. Velocities that arrived with the file are
 * never differenced over -- they are the real thing, and this only fills in
 * the derived properties they came without.
 *
 * @return true when the derived properties are available afterwards.
 */
AVOGADROCORE_EXPORT bool ensureConformerVelocities(Molecule& molecule,
                                                   bool force = false);

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_CONFORMERQUANTITY_H
