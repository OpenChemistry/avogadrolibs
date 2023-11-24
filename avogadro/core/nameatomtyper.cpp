/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "nameatomtyper.h"

#include "atom.h"
#include "elements.h"

namespace Avogadro::Core {

NameAtomTyper::NameAtomTyper(const Molecule* mol) : AtomTyper<std::string>(mol)
{
}

NameAtomTyper::~NameAtomTyper()
{
}

std::string NameAtomTyper::type(const Atom& atom)
{
  return std::string(Elements::name(atom.atomicNumber()));
}

} // namespace Avogadro
