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
 * Output is Kekule only: bond orders are written as they are stored, and no
 * aromatic perception is performed. Stereochemistry is not yet represented.
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
  std::string m_error;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_SMILESWRITER_H
