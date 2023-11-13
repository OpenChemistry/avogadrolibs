/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_GENERICOUTPUT_H
#define AVOGADRO_QUANTUMIO_GENERICOUTPUT_H

#include "avogadroquantumioexport.h"
#include <avogadro/io/fileformat.h>

#include <map>
#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT GenericOutput : public Io::FileFormat
{
public:
  GenericOutput();
  ~GenericOutput() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new GenericOutput; }
  std::string identifier() const override { return "Avogadro: Generic Output"; }
  std::string name() const override { return "Generic Output"; }
  std::string description() const override { return "Generic output format."; }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write output files.
    return false;
  }
};

} // namespace QuantumIO
} // namespace Avogadro

#endif
