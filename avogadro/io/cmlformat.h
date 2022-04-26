/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CMLFORMAT_H
#define AVOGADRO_IO_CMLFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class CmlFormat cmlformat.h <avogadro/io/cmlformat.h>
 * @brief Implementation of the Chemical Markup Language format.
 * @author Marcus D. Hanwell
 */

class AVOGADROIO_EXPORT CmlFormat : public FileFormat
{
public:
  CmlFormat();
  ~CmlFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CmlFormat; }
  std::string identifier() const override { return "Avogadro: CML"; }
  std::string name() const override { return "Chemical Markup Language"; }
  std::string description() const override
  {
    return "TODO: Describe the format.";
  }

  std::string specificationUrl() const override
  {
    return "http://www.xml-cml.org/schema/schema3/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // CMLFORMAT_H
