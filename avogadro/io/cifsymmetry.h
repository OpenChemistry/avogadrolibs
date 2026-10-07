/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CIFSYMMETRY_H
#define AVOGADRO_IO_CIFSYMMETRY_H

#include "avogadroioexport.h"

#include <string>
#include <vector>

namespace Avogadro::Io {

/**
 * @brief The space group information that a CIF file spells out itself.
 *
 * A CIF names its space group by a symbol (which often leaves out the origin
 * choice or the axes) but also lists the symmetry operations, which cannot be
 * ambiguous. Resolving the setting from the operations is what most
 * crystallography programs do.
 */
struct CifSymmetry
{
  /** The symmetry operations ("x,y,z", "-x+1/2,y,-z", ...), as written. */
  std::vector<std::string> operations;

  /** The Hall symbol, if the file gives one. */
  std::string hallSymbol;

  /**
   * The hall number whose operations are exactly @p operations, or 0 if there
   * are none or they are not in the table of Core::SpaceGroups.
   */
  unsigned short hallFromOperations = 0;

  /**
   * The hall number whose Hall symbol is exactly @p hallSymbol (apart from
   * spacing), or 0 if there is none or it is not in the table.
   */
  unsigned short hallFromSymbol = 0;

  /**
   * @return the best hall number: the one given by the operations if there is
   * one, else the one given by the Hall symbol, else 0.
   */
  unsigned short hallNumber() const
  {
    return hallFromOperations != 0 ? hallFromOperations : hallFromSymbol;
  }
};

/**
 * Read the symmetry information from CIF text. Only the first data block is
 * used, as it is the only one that Open Babel reads.
 *
 * The operations are taken from the first loop with a
 * _symmetry_equiv_pos_as_xyz, _space_group_symop_operation_xyz or
 * _space_group_symop.operation_xyz column (or from a single such tag and
 * value); other columns, quoting, comments and text fields are handled. The
 * Hall symbol comes from _symmetry_space_group_name_Hall,
 * _space_group_name_Hall or _space_group.name_Hall.
 *
 * Text that is not a CIF, or that has no symmetry information, gives an
 * empty result. This never fails.
 */
AVOGADROIO_EXPORT CifSymmetry readCifSymmetry(const std::string& cifText);

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_CIFSYMMETRY_H
