#ifndef MOLCORE_BOND_H
#define MOLCORE_BOND_H

#include "molcore.h"

#include <cstddef>

#include "atom.h"

namespace MolCore {

class Molecule;

class MOLCORE_EXPORT Bond
{
public:
  // construction and destruction
  Bond();
  Bond(Molecule *m, size_t i);

  // properties
  bool isValid() const;
  Molecule* molecule() const;
  size_t index() const;
  Atom atom1() const;
  Atom atom2() const;
  unsigned char order() const;

private:
  Molecule *m_molecule;
  size_t m_index;
};

} // end MolCore namespace

#endif // MOLCORE_BOND_H
