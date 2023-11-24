/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "symbolatomtyper.h"

#include "atom.h"
#include "elements.h"

namespace Avogadro::Core {

SymbolAtomTyper::SymbolAtomTyper(const Molecule* mol)
  : AtomTyper<std::string>(mol)
{
}

SymbolAtomTyper::~SymbolAtomTyper()
{
}

std::string SymbolAtomTyper::type(const Atom& atom)
{
  return std::string(Elements::symbol(atom.atomicNumber()));
}

} // namespace Avogadro
