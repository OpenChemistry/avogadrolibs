/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_SYMBOLATOMTYPER_H
#define AVOGADRO_CORE_SYMBOLATOMTYPER_H

#include "avogadrocoreexport.h"

#include <avogadro/core/atomtyper.h>

#include <string>

namespace Avogadro {
namespace Core {

/**
 * @class SymbolAtomTyper symbolatomtyper.h <avogadro/core/symbolatomtyper.h>
 * @brief The SymbolAtomTyper class is a simple implementation of AtomTyper that
 * assigns element symbols to each atom.
 */
class AVOGADROCORE_EXPORT SymbolAtomTyper : public AtomTyper<std::string>
{
public:
  explicit SymbolAtomTyper(const Molecule* mol = nullptr);
  ~SymbolAtomTyper() override;

protected:
  std::string type(const Atom& atom) override;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_SYMBOLATOMTYPER_H
