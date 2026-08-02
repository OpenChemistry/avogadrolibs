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
 * string -- is accepted: Core::kekulize() turns the aromatic ring or ring
 * system back into alternating single and double bond orders, which is how
 * Avogadro stores structures internally. If no assignment satisfies every
 * aromatic atom's valence -- an unkekulizable input -- parsing fails with an
 * error positioned at the first aromatic token in the string, and the
 * molecule is left empty, the same as any other parse failure.
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
 * one. A bracket atom's count is stated in the string, but a bare aromatic
 * atom's implied count depends on the bond orders kekulization produces, so
 * hydrogens for those atoms are added only after kekulization succeeds. As a
 * result, the molecule this class produces orders its atoms as: first, every
 * atom written explicitly in the SMILES, in the order it appears in the
 * string (branches included, depth first); then every hydrogen this class
 * added. The order of the added hydrogens themselves is unspecified -- they
 * are interchangeable -- and does not simply follow their parent atoms'
 * order, since it is now split across two passes.
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
