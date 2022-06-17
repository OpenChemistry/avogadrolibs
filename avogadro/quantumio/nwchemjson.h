/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_NWCHEMJSON_H
#define AVOGADRO_QUANTUMIO_NWCHEMJSON_H

#include "avogadroquantumioexport.h"
#include <avogadro/io/fileformat.h>

namespace Avogadro {
namespace QuantumIO {

/**
 * @class NWChemJson nwchemjson.h <avogadro/quantumio/nwchemjson.h>
 * @brief Implementation of the NWChem JSON format.
 * @author Marcus D. Hanwell
 */

class AVOGADROQUANTUMIO_EXPORT NWChemJson : public Io::FileFormat
{
public:
  NWChemJson();
  ~NWChemJson() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new NWChemJson; }
  std::string identifier() const override { return "Avogadro: NWCHEMJSON"; }
  std::string name() const override { return "NWChem JSON"; }
  std::string description() const override
  {
    return "TODO: Describe the format.";
  }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;
};

} // end QuantumIO namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_NWCHEMJSON_H
