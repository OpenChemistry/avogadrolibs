/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_RINGPERCEIVER_H
#define AVOGADRO_CORE_RINGPERCEIVER_H

#include "avogadrocoreexport.h"

#include <cstddef>
#include <vector>

namespace Avogadro {
namespace Core {

class Molecule;

class AVOGADROCORE_EXPORT RingPerceiver
{
public:
  // construction and destruction
  explicit RingPerceiver(const Molecule* m = nullptr);
  ~RingPerceiver();

  // properties
  void setMolecule(const Molecule* m);
  const Molecule* molecule() const;

  // ring perception
  std::vector<std::vector<size_t>>& rings();

private:
  bool m_ringsPerceived;
  const Molecule* m_molecule;
  std::vector<std::vector<size_t>> m_rings;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_RINGPERCEIVER_H
