/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_NWCHEMLOG_H
#define AVOGADRO_QUANTUMIO_NWCHEMLOG_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/array.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT NWChemLog : public Io::FileFormat
{
public:
  NWChemLog();
  ~NWChemLog() override;
  void outputAll();

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new NWChemLog; }
  std::string identifier() const override { return "Avogadro: NWChem"; }
  std::string name() const override { return "NWChem Log"; }
  std::string description() const override { return "NWChem log file format."; }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out NWChem log files.
    return false;
  }

private:
  void processLine(std::istream& in, Core::Molecule& mol);

  // Read the atoms, and their geometry.
  void readAtoms(std::istream& in, Core::Molecule& mol);

  // Read the projected frequencies.
  void readFrequencies(const std::string& line, std::istream& in,
                       Core::Molecule& mol);

  // Read the projected frequency intensities.
  void readIntensities(std::istream& in, Core::Molecule& mol);

  Core::Array<double> m_frequencies;
  Core::Array<double> m_intensities;
  Core::Array<Core::Array<Vector3>> m_Lx;
};

} // End namespace QuantumIO
} // End namespace Avogadro

#endif
