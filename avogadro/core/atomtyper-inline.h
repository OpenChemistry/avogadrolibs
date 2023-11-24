/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ATOMTYPER_INLINE_H
#define AVOGADRO_CORE_ATOMTYPER_INLINE_H

#include "atomtyper.h"

#include "atom.h"
#include "molecule.h"

namespace Avogadro {
namespace Core {

template <typename OutputType>
AtomTyper<OutputType>::AtomTyper(const Molecule* mol) : m_molecule(mol)
{
}

template <typename OutputType>
AtomTyper<OutputType>::~AtomTyper()
{
}

template <typename OutputType>
void AtomTyper<OutputType>::setMolecule(const Molecule* mol)
{
  if (m_molecule != mol) {
    m_molecule = mol;
    reset();
  }
}

template <typename OutputType>
void AtomTyper<OutputType>::run()
{
  initialize();
  Index numAtoms = m_molecule ? m_molecule->atomCount() : 0;
  for (Index atomId = 0; atomId < numAtoms; ++atomId) {
    Atom atom = m_molecule->atom(atomId);
    m_types.push_back(type(atom));
  }
}

template <typename OutputType>
OutputType AtomTyper<OutputType>::atomType(const Atom& atom)
{
  OutputType result;
  if (atom.isValid() && atom.molecule() == m_molecule) {

    // Return the calculated value if we've already run the typer.
    if (atom.index() < m_types.size()) {
      result = m_types[atom.index()];
    } else {
      initialize();
      result = type(atom);
    }
  }
  return result;
}

template <typename OutputType>
Array<OutputType> AtomTyper<OutputType>::types() const
{
  return m_types;
}

template <typename OutputType>
void AtomTyper<OutputType>::reset()
{
  m_types.clear();
}

template <typename OutputType>
void AtomTyper<OutputType>::initialize()
{
  m_types.reserve(m_molecule ? m_molecule->atomCount() : 0);
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ATOMTYPER_INLINE_H
