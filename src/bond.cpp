
#include "bond.h"

#include "molecule.h"

namespace MolCore {

// === Bond ================================================================ //
/// \class Bond
/// \brief The Bond class represents a bond between two atoms in a
///        molecule.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new, invalid bond object.
Bond::Bond()
  : m_molecule(0),
    m_index(-1)
{
}

/// Creates a bond object representing a bond between atoms \p a and
/// \p b in \p molecule.
Bond::Bond(Molecule *molecule, size_t index)
  : m_molecule(molecule),
    m_index(index)
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns \c true if the bond is valid.
bool Bond::isValid() const
{
  return m_molecule != 0;
}

/// Returns the molecule that the bond is a part of.
Molecule* Bond::molecule() const
{
  return m_molecule;
}

/// Returns the index of the bond in the molecule.
size_t Bond::index() const
{
  return m_index;
}

/// Returns the first atom in the molecule.
Atom Bond::atom1() const
{
  if(m_molecule){
    size_t atomIndex = m_molecule->bondPairs()[m_index].first;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

/// Returns the second atom in the molecule.
Atom Bond::atom2() const
{
  if(m_molecule){
    size_t atomIndex = m_molecule->bondPairs()[m_index].second;

    return m_molecule->atom(atomIndex);
  }

  return Atom();
}

/// Returns the bond order for the bond.
unsigned char Bond::order() const
{
  return m_molecule->bondOrders()[m_index];
}

} // end MolCore namespace
