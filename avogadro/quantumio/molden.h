/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_MOLDEN_H
#define AVOGADRO_QUANTUMIO_MOLDEN_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/array.h>
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
    return Read | Write | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MoldenFile; }
  std::string identifier() const override { return "Avogadro: Molden"; }
  std::string name() const override { return "Molden"; }
  std::string description() const override { return "Molden file format."; }

  std::string specificationUrl() const override
  {
    return "https://www.theochem.ru.nl/molden/molden_format.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  [[nodiscard]] bool read(std::istream& in, Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream& out,
                           const Core::Molecule& molecule) override;

private:
  void outputAll();

  void processLine(std::istream& in);
  void readAtom(const std::vector<std::string>& list);
  bool load(Core::GaussianSet* basis, size_t atomCount);

  // Write helper methods
  void writeAtoms(std::ostream& out, const Core::Molecule& molecule);
  void writeGTO(std::ostream& out, const Core::GaussianSet* basis);
  void writeMO(std::ostream& out, const Core::GaussianSet* basis);
  void writeFrequencies(std::ostream& out, const Core::Molecule& molecule);
  void writeGeometries(std::ostream& out, const Core::Molecule& molecule);

  bool m_cartesianD = true;
  bool m_cartesianF = true;
  bool m_cartesianG = true;

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
  std::vector<double> m_betaOrbitalEnergy;
  std::vector<std::string> m_symmetryLabels;
  std::vector<std::string> m_betaSymmetryLabels;
  std::vector<double> m_MOcoeffs;
  std::vector<double> m_betaMOcoeffs;

  Core::Array<double> m_frequencies;
  Core::Array<double> m_IRintensities;
  Core::Array<double> m_RamanIntensities;
  Core::Array<Core::Array<Vector3>> m_vibDisplacements;

  enum Mode
  {
    Atoms,
    GTO,
    MO,
    Frequencies,
    VibrationalModes,
    Intensities,
    Unrecognized
  };
  Mode m_mode;

  bool m_openShell = false;
  bool m_currentSpinBeta = false; // Track current spin during MO parsing
};

} // namespace QuantumIO
} // namespace Avogadro

#endif
