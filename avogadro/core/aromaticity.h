/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_AROMATICITY_H
#define AVOGADRO_CORE_AROMATICITY_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <vector>

namespace Avogadro::Core {

class Molecule;

/** Reported for an atom that cannot take part in an aromatic system. */
constexpr signed char NotAromaticCandidate = -1;

/**
 * @class AromaticityPerceiver aromaticity.h <avogadro/core/aromaticity.h>
 * @brief Perceive which atoms and bonds belong to an aromatic system.
 *
 * Results are derived, not stored: like RingPerceiver, this takes a molecule
 * and answers questions about it, leaving the molecule untouched. Perception
 * runs on first use and is cached until setMolecule() is called again.
 *
 * The molecule is read in its Kekule form -- alternating single and double
 * bond orders, which is how Avogadro stores structures -- so no kekulization
 * is required or performed.
 *
 * Each candidate atom is assigned a pi electron contribution, and a ring is
 * aromatic when its contributions sum to 4n+2 and every atom is a candidate.
 * Fused rings are also tested as a whole, which is what makes azulene aromatic
 * even though neither of its rings satisfies the rule alone.
 *
 * The contribution table is hand-transcribed chemistry and is the part of this
 * class most in need of review; piContributions() exposes it directly so it
 * can be tested without going through the ring arithmetic.
 */
class AVOGADROCORE_EXPORT AromaticityPerceiver
{
public:
  /**
   * Which set of rules to apply. Only Default exists so far; the enum is here
   * so that adding a model later does not change this class's interface.
   */
  enum class Model
  {
    Default //!< Broadly the model RDKit applies by default.
  };

  explicit AromaticityPerceiver(const Molecule* m = nullptr,
                                Model model = Model::Default);
  ~AromaticityPerceiver() = default;

  void setMolecule(const Molecule* m);
  const Molecule* molecule() const { return m_molecule; }
  Model model() const { return m_model; }

  /**
   * Atoms grouped into fused ring systems: the connected components of the
   * ring bonds. Aromaticity is decided over these as well as over individual
   * rings.
   */
  const std::vector<std::vector<Index>>& ringSystems() const;

  /**
   * Per-atom pi electron contribution, or NotAromaticCandidate for an atom
   * that cannot be part of an aromatic system at all.
   */
  const std::vector<signed char>& piContributions() const;

  /** One entry per atom, true where the atom is in an aromatic system. */
  const std::vector<bool>& aromaticAtoms() const;

  /** One entry per bond, true where both ends share an aromatic system. */
  const std::vector<bool>& aromaticBonds() const;

private:
  void perceive() const;

  const Molecule* m_molecule;
  Model m_model;

  mutable bool m_perceived;
  mutable std::vector<std::vector<Index>> m_ringSystems;
  mutable std::vector<signed char> m_piContributions;
  mutable std::vector<bool> m_aromaticAtoms;
  mutable std::vector<bool> m_aromaticBonds;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_AROMATICITY_H
