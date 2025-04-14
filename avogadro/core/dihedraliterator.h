/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_DIHEDRALITERATOR_H
#define AVOGADRO_CORE_DIHEDRALITERATOR_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <tuple>

namespace Avogadro::Core {

class Molecule;

using Dihedral = std::tuple<Index, Index, Index, Index>;

class AVOGADROCORE_EXPORT DihedralIterator
{
public:
  /**
   * Constructor.
   */
  DihedralIterator(const Molecule* mol);

  ~DihedralIterator() = default;

  Dihedral* operator*() { return &m_current; }

  Dihedral begin();

  Dihedral end() const
  {
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex, MaxIndex);
  }

  Dihedral operator++();

  bool operator!=(const DihedralIterator& other)
  {
    return m_current != other.m_current;
  }

private:
  Dihedral m_current;
  Index m_i, m_jk, m_l;
  const Molecule* m_mol;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_DIHEDRALITERATOR_H
