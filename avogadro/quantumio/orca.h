/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_ORCA_H
#define AVOGADRO_QUANTUMIO_ORCA_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/array.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <map>
#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT ORCAOutput : public Io::FileFormat
{
public:
  ORCAOutput();
  ~ORCAOutput() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new ORCAOutput; }
  std::string identifier() const override { return "Avogadro: Orca"; }
  std::string name() const override { return "Orca"; }
  std::string description() const override { return "Orca output format."; }

  std::string specificationUrl() const override { return ""; }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out Orca output files.
    return false;
  }

private:
  void outputAll();

  void processLine(std::istream& in, Core::GaussianSet* basis);
  void load(Core::GaussianSet* basis);

  // OrcaStuff
  void orcaWarningMessage(const std::string& m);
  Core::GaussianSet::orbital orbitalIdx(std::string txt);
  bool m_orcaSuccess;

  std::vector<std::string> m_atomLabel;
  std::vector<std::string> m_basisAtomLabel;

  std::vector<int> m_atomNums;
  std::vector<Eigen::Vector3d> m_atomPos;

  std::vector<int> shellFunctions;
  std::vector<Core::GaussianSet::orbital> shellTypes;
  std::vector<std::vector<int>> m_orcaNumShells;
  std::vector<std::vector<Core::GaussianSet::orbital>> m_orcaShellTypes;
  int m_nGroups;

  std::vector<std::vector<std::vector<Eigen::Vector2d>*>*> m_basisFunctions;

  enum mode
  {
    Atoms,
    GTO,
    MO,
    OrbitalEnergies,
    Charges,
    Frequencies,
    VibrationalModes,
    IR,
    Raman,
    Electronic,
    NMR,
    NotParsing,
    Unrecognized
  };

  double m_coordFactor;
  mode m_currentMode;
  int m_electrons;

  bool m_openShell;
  bool m_readBeta;

  int m_homo;

  int m_currentAtom;
  unsigned int m_numBasisFunctions;
  std::vector<Core::GaussianSet::orbital> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_a;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_MOcoeffs;
  std::vector<double> m_betaOrbitalEnergy;
  std::vector<double> m_BetaMOcoeffs;

  std::string m_chargeType;
  std::map<std::string, MatrixX> m_partialCharges;

  Core::Array<double> m_frequencies;
  Core::Array<double> m_IRintensities;
  Core::Array<double> m_RamanIntensities;
  Core::Array<Core::Array<Vector3>> m_vibDisplacements;
};

} // namespace QuantumIO
} // namespace Avogadro

#endif
