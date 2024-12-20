/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_CJSONFORMAT_H
#define AVOGADRO_IO_CJSONFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Core {
class GaussianSet;
}
namespace Io {

/**
 * @class CjsonFormat cjsonformat.h <avogadro/io/cjsonformat.h>
 * @brief Implementation of the Chemical JSON format.
 */

class AVOGADROIO_EXPORT CjsonFormat : public FileFormat
{
public:
  CjsonFormat() = default;
  ~CjsonFormat() override = default;

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new CjsonFormat; }
  std::string identifier() const override { return "Avogadro: CJSON"; }
  std::string name() const override { return "Chemical JSON"; }
  std::string description() const override
  {
    return "CJSON format is a lightweight intermediate format used to exchange "
           "information between Avogadro and other data parsing applications";
  }

  std::string specificationUrl() const override
  {
    return "https://github.com/openchemistry/chemicaljson";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;

  // internal - to allow JSON or MsgPack to be written
  bool deserialize(std::istream& in, Core::Molecule& molecule, bool json);
  bool serialize(std::ostream& out, const Core::Molecule& molecule, bool json);
};

} // namespace Io
} // namespace Avogadro

#endif // AVOGADRO_IO_CJSONFORMAT_H
