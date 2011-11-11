#ifndef MOLCORE_RINGPERCEIVER_H
#define MOLCORE_RINGPERCEIVER_H

#include "molcore.h"

#include <vector>
#include <cstddef>

namespace MolCore {

class Molecule;

class MOLCORE_EXPORT RingPerceiver
{
public:
  // construction and destruction
  RingPerceiver(const Molecule *molecule = 0);
  ~RingPerceiver();

  // properties
  void setMolecule(const Molecule *molecule);
  const Molecule* molecule() const;

  // ring perception
  std::vector<std::vector<size_t> >& rings();

private:
  bool m_ringsPerceived;
  const Molecule *m_molecule;
  std::vector<std::vector<size_t> > m_rings;
};

} // end MolCore namespace

#endif // MOLCORE_RINGPERCEIVER_H
