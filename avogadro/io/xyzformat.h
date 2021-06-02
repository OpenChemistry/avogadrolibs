/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_XYZFORMAT_H
#define AVOGADRO_IO_XYZFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class XyzFormat xyzformat.h <avogadro/io/xyzformat.h>
 * @brief Implementation of the generic xyz format.
 * @author Allison Vacanti
 */

class AVOGADROIO_EXPORT XyzFormat : public FileFormat
{
public:
  XyzFormat();
  ~XyzFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new XyzFormat; }
  std::string identifier() const override { return "Avogadro: XYZ"; }
  std::string name() const override { return "XYZ"; }
  std::string description() const override
  {
    return "Generic format that tabulates atomic symbols and 3D positions.";
  }

  std::string specificationUrl() const override
  {
    return "http://openbabel.org/wiki/XYZ";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& molecule) override;
  bool write(std::ostream& outStream, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_XYZFORMAT_H
