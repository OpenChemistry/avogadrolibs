/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_QCSCHEMA_H
#define AVOGADRO_QUANTUMIO_QCSCHEMA_H

#include "avogadroquantumioexport.h"
#include <avogadro/io/fileformat.h>

namespace Avogadro {
namespace QuantumIO {

/**
 * @class QCSchema qcschema.h <avogadro/quantumio/qcschema.h>
 * @brief Implementation of the MolSSI QCSchema format and WebMO variant
 * @author Geoffrey R. Hutchison
 */

class AVOGADROQUANTUMIO_EXPORT QCSchema : public Io::FileFormat
{
public:
  QCSchema();
  ~QCSchema() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new QCSchema; }
  std::string identifier() const override { return "Avogadro: QCSchema"; }
  std::string name() const override { return "QCSchema JSON"; }
  std::string description() const override
  {
    return "MolSSI QCSchema JSON format.";
  }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override
  {
    // Empty, as we do not currently write QC_SCHEMA files.
    return false;
  }
};

} // namespace QuantumIO
} // namespace Avogadro

#endif // AVOGADRO_IO_NWCHEMJSON_H
