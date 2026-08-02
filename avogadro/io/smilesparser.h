/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_SMILESPARSER_H
#define AVOGADRO_IO_SMILESPARSER_H

#include "avogadroioexport.h"

#include <avogadro/core/avogadrocore.h>

#include <cstddef>
#include <string>
#include <vector>

namespace Avogadro::Core {
class Molecule;
}

namespace Avogadro::Io {

/**
 * @class SmilesParser smilesparser.h <avogadro/io/smilesparser.h>
 * @brief Parse a SMILES string into a molecule.
 *
 * This is the inverse of SmilesWriter, and follows the OpenSMILES grammar
 * (http://opensmiles.org/opensmiles.html): the organic subset, bracket atoms,
 * branches, ring closures and dot-disconnected components.
 *
 * Aromatic input -- a lowercase atom, or an aromatic bond, anywhere in the
 * string -- is rejected outright rather than guessed at. Turning an aromatic
 * ring back into alternating single and double bonds (kekulization) is not
 * implemented yet; the rejection is a single block in the .cpp file, marked
 * as the place a future kekulizer replaces.
 *
 * Chirality markers and the directional bond markers '/' and '\' are parsed
 * -- so the rest of the string still makes sense -- but the stereochemistry
 * they describe is discarded: a freshly parsed molecule has no coordinates,
 * and Avogadro represents stereochemistry through coordinates rather than
 * through a stored descriptor. warnings() reports this once per parse, not
 * once per occurrence.
 *
 * Avogadro's convention is that every hydrogen is a real atom in the graph,
 * so every hydrogen this class infers -- from the organic subset valence
 * model on a bare atom, or from a bracket's H count -- is materialized as
 * one. An atom's final bond order sum, and so its implied hydrogen count, is
 * not known until its ring closures have all been seen, so this happens in a
 * second pass after the rest of the molecule is built. As a result, the
 * molecule this class produces orders its atoms as: first, every atom
 * written explicitly in the SMILES, in the order it appears in the string
 * (branches included, depth first); then every hydrogen this class added,
 * grouped by the atom it was added to and in that atom's order, in no
 * particular order within a group (they are interchangeable).
 */
class AVOGADROIO_EXPORT SmilesParser
{
public:
  SmilesParser() = default;
  ~SmilesParser() = default;

  /**
   * Parse @a smiles into @a molecule, replacing any atoms and bonds it
   * already had. The molecule is left with none of either on failure.
   * @return True on success.
   */
  bool parse(const std::string& smiles, Core::Molecule& molecule);

  /**
   * @return A description of the last failure, or an empty string.
   */
  const std::string& error() const { return m_error; }

  /**
   * @return Character offset into the input at which the last failure was
   * detected.
   */
  size_t errorPosition() const { return m_errorPosition; }

  /**
   * @return Non-fatal notes about information the parse discarded.
   */
  const std::vector<std::string>& warnings() const { return m_warnings; }

  /**
   * Daylight atom map classes, one entry per atom of the molecule produced,
   * zero where the atom carried none.
   *
   * These are exposed but never applied: a map class is data from the input,
   * and using it to place an atom would let a malformed or hostile string
   * reorder or alias atoms. Callers wanting to correlate with a mapped write
   * must subtract one, since SmilesWriter emits index + 1.
   */
  const std::vector<size_t>& atomMaps() const { return m_atomMaps; }

private:
  std::string m_error;
  size_t m_errorPosition = 0;
  std::vector<std::string> m_warnings;
  std::vector<size_t> m_atomMaps;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_SMILESPARSER_H
