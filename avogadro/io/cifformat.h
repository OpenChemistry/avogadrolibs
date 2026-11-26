/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CIFFORMAT_H
#define AVOGADRO_IO_CIFFORMAT_H

#include "fileformat.h"

namespace Avogadro::Io {

/**
 * @class CifFormat cifformat.h <avogadro/io/cifformat.h>
 * @brief Reader and P1 writer for small-molecule CIF files.
 *
 * The reader keeps the asymmetric unit of the file and records the space
 * group of the molecule (see applyCifSymmetry()), or the operations of the
 * file when they match no table entry; it does not fill the cell.
 * A file without fractional coordinates (a macromolecular mmCIF) or one this
 * reader cannot make sense of is handed to another reader registered for
 * "cif", normally the Open Babel plugin.
 *
 * The writer makes a P1 file: a molecule with a space group other than P1 (or
 * with stored operations) is filled out to all the atoms of its cell first, and
 * no bonds are written (a bond across a cell face needs a symmetry code).
 *
 * The site occupancy of each atom is stored (see Core::Molecule::occupancy()),
 * but only when some site is not a full one, and a missing or unreadable value
 * counts as 1. The disorder assembly and group labels of the atoms are stored
 * as written (see Core::Molecule::disorderGroup()) when any atom has a group,
 * and written back as @c _atom_site_disorder_assembly and
 * @c _atom_site_disorder_group.
 *
 * The read option "disorder" chooses what to do with disordered sites. With
 * "major" (the default) only one configuration is read: in each disorder
 * assembly the group with the highest mean occupancy is kept (the first in the
 * file on a tie; a lone group needs 0.5 or more) and the atoms of the other
 * groups are dropped. Groups with a negative label (disorder across a symmetry
 * element) and atoms without a group are always kept. With "all" every atom of
 * every group is read; bonds between alternatives are never perceived (see
 * Core::Molecule::areDisorderAlternatives()).
 *
 * Displacement parameters are not stored. The occupancies also choose the major
 * group.
 */
class AVOGADROIO_EXPORT CifFormat : public FileFormat
{
public:
  CifFormat() = default;
  ~CifFormat() override = default;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CifFormat; }
  std::string identifier() const override { return "Avogadro: CIF"; }
  std::string name() const override { return "CIF"; }
  std::string description() const override
  {
    return "Crystallographic Information File: unit cell, symmetry and "
           "atoms of a crystal structure.";
  }

  std::string specificationUrl() const override
  {
    return "https://www.iucr.org/resources/cif/spec";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& inStream,
                          Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream& outStream,
                           const Core::Molecule& molecule) override;
};

} // namespace Avogadro::Io

#endif // AVOGADRO_IO_CIFFORMAT_H
