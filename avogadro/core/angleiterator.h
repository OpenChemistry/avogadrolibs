/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ANGLEITERATOR_H
#define AVOGADRO_CORE_ANGLEITERATOR_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <tuple>

namespace Avogadro::Core {

class Molecule;

using Angle = std::tuple<Index, Index, Index>;

class AVOGADROCORE_EXPORT AngleIterator
{
public:
  /**
   * Constructor.
   */
  AngleIterator(const Molecule* mol);

  ~AngleIterator() {}

  Angle* operator*() { return &m_current; }

  Angle begin();

  Angle end() const
  {
    return std::make_tuple(Avogadro::MaxIndex, Avogadro::MaxIndex,
                           Avogadro::MaxIndex);
  }

  Angle operator++();

  bool operator!=(const AngleIterator& other)
  {
    return (m_a != other.m_a || m_b != other.m_b || m_c != other.m_c);
  }

private:
  // m_b is the current vertex
  // m_a and m_c are instead index into the neighbors of m_b
  Index m_a, m_b, m_c;
  Angle m_current;
  const Molecule* m_mol;
};

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_ANGLEITERATOR_H
