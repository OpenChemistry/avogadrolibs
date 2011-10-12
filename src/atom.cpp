
#include "atom.h"

#include "molecule.h"

namespace MolCore {

// === Atom ================================================================ //
/// \class Atom
/// \brief The Atom class represents an atom in a molecule.

/// Creates a new, invalid atom object.
Atom::Atom()
  : m_molecule(0),
    m_index(-1)
{
}

/// Creates a new atom object representing the atom at \p index in
/// \p molecule.
Atom::Atom(Molecule *molecule, size_t index)
  : m_molecule(molecule),
    m_index(index)
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns \c true if the atom is valid.
bool Atom::isValid() const
{
  return m_molecule != 0;
}

/// Returns the molecule the atom is a part of.
Molecule* Atom::molecule() const
{
  return m_molecule;
}

/// Returns the atom's index in the molecule.
size_t Atom::index() const
{
  return m_index;
}

/// Sets the atom's atomic number to \p atomicNumber.
void Atom::setAtomicNumber(unsigned char atomicNumber)
{
  m_molecule->atomicNumbers()[m_index] = atomicNumber;
}

/// Returns the atom's atomic number.
unsigned char Atom::atomicNumber() const
{
  return m_molecule->atomicNumbers()[m_index];
}

} // end MolCore namespace
