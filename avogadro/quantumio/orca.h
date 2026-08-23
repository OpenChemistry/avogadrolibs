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

  [[nodiscard]] bool read(std::istream& in, Core::Molecule& molecule) override;
  [[nodiscard]] bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out Orca output files.
    return false;
  }

private:
  void outputAll();

  void processLine(std::istream& in, Core::GaussianSet* basis);
  void load(Core::GaussianSet* basis);
  void clearBasisFunctions();

  void parseMCD();

  // OrcaStuff
  void orcaWarningMessage(const std::string& m);
  Core::GaussianSet::orbital orbitalIdx(std::string txt);
  bool m_orcaSuccess = true;

  std::vector<std::string> m_atomLabel;
  std::vector<std::string> m_basisAtomLabel;

  std::vector<int> m_atomNums;
  std::vector<Eigen::Vector3d> m_atomPos;
  std::vector<std::vector<Eigen::Vector3d>> m_coordSets;
  std::vector<double> m_energies;

  Vector3 m_dipoleMoment = Vector3::Zero();

  std::vector<std::vector<int>> m_bondOrders;

  std::vector<int> shellFunctions;
  std::vector<Core::GaussianSet::orbital> shellTypes;
  std::vector<std::vector<int>> m_orcaNumShells;
  std::vector<std::vector<Core::GaussianSet::orbital>> m_orcaShellTypes;
  int m_nGroups = 0;

  std::vector<std::vector<std::vector<Eigen::Vector2d>*>*> m_basisFunctions;

  enum mode
  {
    Atoms,
    GTO,
    MO,
    OrbitalEnergies,
    Charges,
    HirshfeldCharges,
    Frequencies,
    VibrationalModes,
    IR,
    Raman,
    VCD, // vibrational circular dichroism
    Electronic,
    ECD, // electronic circular dichroism
    MCD, // magnetic circular dichroism
    NMR,
    BondOrders,
    NotParsing,
    Unrecognized
  };

  // Bohr; the only assignment (CARTESIAN COORDINATES (A.U.)) also uses 1.0
  double m_coordFactor = 1.0;
  mode m_currentMode = NotParsing;
  int m_electrons = 0;

  bool m_openShell = false;
  bool m_readBeta = false;

  int m_homo = 0;
  int m_charge = 0;
  int m_spin = 1;
  double m_totalEnergy = 0.0;

  int m_currentAtom = 0;
  unsigned int m_numBasisFunctions = 0;
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

  // Vibrational data for the geometry currently being parsed. A transition
  // state search recomputes the Hessian every few cycles, so a file can hold
  // several of these; completed sets are moved into m_vibrationSets.
  Core::Array<double> m_frequencies;
  Core::Array<double> m_IRintensities;
  Core::Array<double> m_RamanIntensities;
  Core::Array<double> m_vcdIntensities;
  Core::Array<Core::Array<Vector3>> m_vibDisplacements;

  /** One completed set of vibrational data, and the geometry it belongs to. */
  struct VibrationSet
  {
    size_t conformerIndex = 0;
    Core::Array<double> frequencies;
    Core::Array<double> irIntensities;
    Core::Array<double> ramanIntensities;
    Core::Array<double> vcdIntensities;
    Core::Array<Core::Array<Vector3>> displacements;
  };
  std::vector<VibrationSet> m_vibrationSets;

  /**
   * The conformer the set being accumulated belongs to: the number of
   * geometries already pushed to m_coordSets when its header was seen, which
   * is the index of the most recently parsed geometry.
   */
  size_t m_vibrationConformer = 0;

  /**
   * Whether any normal mode displacement has been read for the set being
   * accumulated. The frequency block allocates the displacement array up
   * front, so its size alone cannot tell a complete set from a job that died
   * before printing NORMAL MODES.
   */
  bool m_haveNormalModes = false;

  /**
   * Move the vibrational data accumulated so far into m_vibrationSets, and
   * reset the accumulators for the next Hessian. Does nothing when nothing
   * has been accumulated.
   */
  void flushVibrationData();

  Core::Array<double> m_electronicTransitions; // in eV
  Core::Array<double> m_electronicIntensities;
  Core::Array<double> m_electronicRotations; // for CD

  Core::Array<double> m_magneticTransitions; // in cm^-1
  Core::Array<double> m_magneticCD;          // for MCD

  Core::Array<double> m_nmrShifts; // for NMR (in ppm)
};

} // namespace QuantumIO
} // namespace Avogadro

#endif
