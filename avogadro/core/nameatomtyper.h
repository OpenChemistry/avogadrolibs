/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_NAMEATOMTYPER_H
#define AVOGADRO_CORE_NAMEATOMTYPER_H

#include "avogadrocoreexport.h"

#include <avogadro/core/atomtyper.h>

#include <string>

namespace Avogadro {
namespace Core {

/**
 * @class NameAtomTyper nameatomtyper.h <avogadro/core/nameatomtyper.h>
 * @brief The NameAtomTyper class is a simple implementation of AtomTyper that
 * assigns element names to each atom.
 */
class AVOGADROCORE_EXPORT NameAtomTyper : public AtomTyper<std::string>
{
public:
  explicit NameAtomTyper(const Molecule* mol = nullptr);
  ~NameAtomTyper() override;

protected:
  std::string type(const Atom& atom) override;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_NAMEATOMTYPER_H
