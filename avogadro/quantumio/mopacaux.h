/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_MOPACAUX_H
#define AVOGADRO_QUANTUMIO_MOPACAUX_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/array.h>
#include <avogadro/core/slaterset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT MopacAux : public Io::FileFormat
{
public:
  MopacAux();
  ~MopacAux() override;
  void outputAll();

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new MopacAux; }
  std::string identifier() const override { return "Avogadro: MOPAC"; }
  std::string name() const override { return "MOPAC AUX"; }
  std::string description() const override { return "MOPAC AUX file format."; }

  std::string specificationUrl() const override
  {
    return "http://openmopac.net/manual/auxiliary.html";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out MOPAC AUX files.
    return false;
  }

private:
  void processLine(std::istream& in);
  void load(Core::SlaterSet* basis);
  std::vector<int> readArrayElements(std::istream& in, unsigned int n);
  std::vector<int> readArrayI(std::istream& in, unsigned int n);
  std::vector<double> readArrayD(std::istream& in, unsigned int n);
  std::vector<int> readArraySym(std::istream& in, unsigned int n);
  std::vector<Vector3> readArrayVec(std::istream& in, unsigned int n);
  bool readOverlapMatrix(std::istream& in, unsigned int n);
  bool readEigenVectors(std::istream& in, unsigned int n);
  bool readDensityMatrix(std::istream& in, unsigned int n);
  bool readVibrationFrequencies(std::istream& in, unsigned int n);
  bool readVibrationIntensities(std::istream& in, unsigned int n);
  bool readNormalModes(std::istream& in, unsigned int n);

  int m_electrons;
  std::vector<int> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_MOcoeffs;

  std::vector<int> m_atomIndex;
  std::vector<int> m_atomSym;
  std::vector<int> m_atomNums;
  std::vector<double> m_zeta;
  std::vector<int> m_pqn;
  std::vector<Eigen::Vector3d> m_atomPos;

  std::vector<double> m_frequencies;
  std::vector<double> m_irIntensities;
  std::vector<Eigen::Vector3d> m_normalModes;

  Eigen::MatrixXd m_overlap; /// Overlap matrix
  Eigen::MatrixXd m_eigenVectors;
  Eigen::MatrixXd m_density; /// Total density matrix
};

} // End namespace QuantumIO
} // End namespace Avogadro

#endif
