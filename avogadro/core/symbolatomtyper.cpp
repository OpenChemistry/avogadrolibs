/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "symbolatomtyper.h"

#include "elements.h"

namespace Avogadro::Core {

SymbolAtomTyper::SymbolAtomTyper(const Molecule* mol)
  : AtomTyper<std::string>(mol)
{
}

std::string SymbolAtomTyper::type(const Atom& atom)
{
  return std::string(Elements::symbol(atom.atomicNumber()));
}

} // namespace Avogadro::Core
