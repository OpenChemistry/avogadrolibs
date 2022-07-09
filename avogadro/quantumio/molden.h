/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_MOLDEN_H
#define AVOGADRO_QUANTUMIO_MOLDEN_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT MoldenFile : public Io::FileFormat
{
public:
  MoldenFile();
  ~MoldenFile() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MoldenFile; }
  std::string identifier() const override { return "Avogadro: Molden"; }
  std::string name() const override { return "Molden"; }
  std::string description() const override { return "Molden file format."; }

  std::string specificationUrl() const override
  {
    return "http://www.cmbi.ru.nl/molden/molden_format.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out Molden files.
    return false;
  }

private:
  void outputAll();

  void processLine(std::istream& in);
  void readAtom(const std::vector<std::string>& list);
  void load(Core::GaussianSet* basis);

  double m_coordFactor;
  int m_electrons;
  unsigned int m_numBasisFunctions;
  std::vector<int> m_aNums;
  std::vector<double> m_aPos;
  std::vector<Core::GaussianSet::orbital> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_a;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_MOcoeffs;

  enum Mode
  {
    Atoms,
    GTO,
    MO,
    Unrecognized
  };
  Mode m_mode;
};

} // End namespace
}

#endif
