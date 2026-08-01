/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_SMILESWRITER_H
#define AVOGADRO_IO_SMILESWRITER_H

#include "avogadroioexport.h"

#include <avogadro/core/avogadrocore.h>

#include <string>

namespace Avogadro::Core {
class Molecule;
}

namespace Avogadro::Io {

/**
 * @class SmilesWriter smileswriter.h <avogadro/io/smileswriter.h>
 * @brief Serialize a molecule to a SMILES string.
 *
 * Tetrahedral chirality and double bond direction markers are read out of the
 * molecule's coordinates, so they are written only for a molecule that has
 * them; a structure without 3D positions is written without stereochemistry
 * rather than with a guess. Which centres count as stereogenic is decided
 * constitutionally, within the limits documented in atomequivalence_p.h.
 *
 * Where a source marked a configuration undefined -- see Core::stereo.h --
 * that is honoured and no descriptor is written, since the coordinates in that
 * case are a placement rather than a claim.
 */

class AVOGADROIO_EXPORT SmilesWriter
{
public:
  /**
   * How hydrogens are represented in the output.
   */
  enum class HydrogenMode
  {
    /** Inferred from the valence model, so methane is written "C". */
    Implicit,
    /** A count inside the bracket, so methane is written "[CH4]". */
    Bracket,
    /** Separate atoms, so methane is written "[H][C]([H])([H])[H]". */
    Explicit
  };

  SmilesWriter() = default;
  ~SmilesWriter() = default;

  /**
   * Set how hydrogens are represented. Note that atomMaps() overrides this,
   * see setAtomMaps().
   */
  void setHydrogenMode(HydrogenMode mode) { m_hydrogenMode = mode; }
  HydrogenMode hydrogenMode() const { return m_hydrogenMode; }

  /**
   * Emit each atom's index as a Daylight atom map class, so that the string
   * can be correlated back to the molecule it came from.
   *
   * Classes are written one-based, because Daylight assigns class zero the
   * meaning "unmapped"; a consumer reading the classes back must subtract one
   * to recover the Avogadro atom index.
   *
   * This implies HydrogenMode::Explicit. A hydrogen folded into a bracket
   * count has nowhere to carry a class, and in Avogadro that hydrogen is a
   * real atom with a real index, so folding it would silently produce a
   * partial mapping.
   */
  void setAtomMaps(bool enable) { m_atomMaps = enable; }
  bool atomMaps() const { return m_atomMaps; }

  /**
   * Write perceived aromatic rings in the lowercase form, so benzene is
   * "c1ccccc1" rather than "C1=CC=CC=C1". Both describe the same molecule;
   * the lowercase form is what most toolkits produce and expect.
   *
   * Perception is Core::AromaticityPerceiver; anything it does not recognise
   * is written with its bond orders as stored.
   */
  void setAromatic(bool enable) { m_aromatic = enable; }
  bool aromatic() const { return m_aromatic; }

  /**
   * @return The hydrogen mode that will actually be used, after applying the
   * implication described in setAtomMaps().
   */
  HydrogenMode effectiveHydrogenMode() const;

  /**
   * Write @a molecule to @a smiles.
   * @return True on success, false on failure, in which case error() gives
   * more detail and @a smiles is left empty.
   */
  bool write(const Core::Molecule& molecule, std::string& smiles);

  /**
   * @return A description of the last failure, or an empty string.
   */
  const std::string& error() const { return m_error; }

private:
  HydrogenMode m_hydrogenMode = HydrogenMode::Implicit;
  bool m_atomMaps = false;
  bool m_aromatic = true;
  std::string m_error;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_SMILESWRITER_H
