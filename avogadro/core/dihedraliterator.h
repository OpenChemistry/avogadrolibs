/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_DIHEDRALITERATOR_H
#define AVOGADRO_CORE_DIHEDRALITERATOR_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <vector>
#include <tuple>

namespace Avogadro {
namespace Core {

class Molecule;

typedef std::tuple<Index, Index, Index, Index> Dihedral;

class AVOGADROCORE_EXPORT DihedralIterator
{
public:
  /**
   * Constructor.
   */
  DihedralIterator(const Molecule *mol);

  ~DihedralIterator() {}

  Dihedral* operator*() {
    return &m_current;
  }

  Dihedral begin();

  Dihedral end() const {
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
  }

  Dihedral operator++();

  bool operator!=(const DihedralIterator& other ) {
    return m_current != other.m_current;
  }

private:
  Dihedral     m_current;
  const Molecule* m_mol;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_DIHEDRALITERATOR_H
