/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLEITERATOR_H
#define AVOGADRO_CORE_ANGLEITERATOR_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <vector>
#include <tuple>

namespace Avogadro {
namespace Core {

class Molecule;

typedef std::tuple<Index, Index, Index> Angle;

class AVOGADROCORE_EXPORT AngleIterator
{
public:
  /**
   * Constructor.
   */
  AngleIterator(const Molecule *mol);

  ~AngleIterator() {}

  Angle* operator*() {
    return &m_current;
  }

  Angle begin();

  Angle end() const {
    return std::make_tuple(MaxIndex, MaxIndex, MaxIndex);
  }

  Angle operator++();

  bool operator!=(const AngleIterator& other ) {
    return m_current != other.m_current;
  }

private:
  Angle     m_current;
  const Molecule* m_mol;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ANGLEITERATOR_H
