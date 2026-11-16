/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CIFSYMMETRY_H
#define AVOGADRO_IO_CIFSYMMETRY_H

#include "avogadroioexport.h"

#include <string>
#include <string_view>
#include <vector>

namespace Avogadro::Core {
class Molecule;
}

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
   * The name of the space group for display: the Hermann-Mauguin symbol if the
   * file gives one, else the Hall symbol, else empty.
   */
  std::string name;

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

  /**
   * @return true if the file lists several operations that are not those of
   * any table entry (a non-standard setting such as A-1 or I-1, or an origin
   * shift). The table cannot describe such a file, so the molecule keeps its
   * operations instead of a Hall number; see applyCifSymmetry().
   */
  bool hasUntabulatedOperations() const
  {
    return operations.size() > 1 && hallFromOperations == 0;
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
 * _space_group_name_Hall or _space_group.name_Hall, and the name from
 * _symmetry_space_group_name_H-M, _space_group_name_H-M_alt or
 * _space_group.name_H-M_alt.
 *
 * Text that is not a CIF, or that has no symmetry information, gives an
 * empty result. This never fails.
 */
AVOGADROIO_EXPORT CifSymmetry readCifSymmetry(std::string_view cifText);

/**
 * Build a CifSymmetry from the symmetry operations and the Hall symbol that a
 * file gives, looking both up in the table of Core::SpaceGroups. Either may be
 * empty. @p name is the Hermann-Mauguin symbol for display (CifSymmetry::name),
 * which falls back to the Hall symbol. readCifSymmetry() uses this too, so
 * every reader resolves them the same way.
 */
AVOGADROIO_EXPORT CifSymmetry makeCifSymmetry(
  const std::vector<std::string>& operations, const std::string& hallSymbol,
  const std::string& name = std::string());

/**
 * Set the space group of @p molecule, which holds the asymmetric unit read
 * from a CIF file, from what the file spells out itself. Does nothing if the
 * molecule has no unit cell.
 *
 * Operations that match no table entry are kept on the molecule instead of a
 * Hall number (Core::SpaceGroups::setStoredOperations()): the Hall number is 0,
 * the international number a reader may have guessed from the name is removed,
 * and the atoms are not expanded, so the user keeps the asymmetric unit and
 * Fill Unit Cell uses the operations of the file. If they cannot be parsed, or
 * for any other file, the Hall number is that of the operations, else that of
 * the Hall symbol, and a molecule keeps the group a reader already found if
 * the file lists only the identity (the operations were stripped, or every
 * atom is already present) while the reader named a larger group. Nothing is
 * changed if the file identifies no group. The bonds are never touched.
 */
AVOGADROIO_EXPORT void applyCifSymmetry(const CifSymmetry& symmetry,
                                        Core::Molecule& molecule);

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_CIFSYMMETRY_H
