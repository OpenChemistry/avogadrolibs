/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_RINGPERCEIVER_H
#define AVOGADRO_CORE_RINGPERCEIVER_H

#include "avogadrocoreexport.h"

#include <cstddef>
#include <vector>

namespace Avogadro::Core {

class Molecule;

class AVOGADROCORE_EXPORT RingPerceiver
{
public:
  // construction and destruction
  explicit RingPerceiver(const Molecule* m = nullptr);
  ~RingPerceiver() = default;

  // properties
  void setMolecule(const Molecule* m);
  const Molecule* molecule() const;

  // ring perception

  /**
   * The smallest set of smallest rings, each as a list of atom indices in the
   * order they are traversed. A ring is not defined below three atoms, so
   * every entry holds at least three and the bond closing it joins the last
   * atom back to the first.
   */
  std::vector<std::vector<size_t>>& rings();

private:
  bool m_ringsPerceived;
  const Molecule* m_molecule;
  std::vector<std::vector<size_t>> m_rings;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_RINGPERCEIVER_H
