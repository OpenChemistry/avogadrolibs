/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008-2009 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_MOPACAUX_H
#define AVOGADRO_QUANTUMIO_MOPACAUX_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/slaterset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT MopacAux : public Io::FileFormat
{
public:
  MopacAux();
  ~MopacAux() AVO_OVERRIDE;
  void outputAll();

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new MopacAux; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: MOPAC"; }
  std::string name() const AVO_OVERRIDE { return "MOPAC AUX"; }
  std::string description() const AVO_OVERRIDE
  {
    return "MOPAC AUX file format.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://openmopac.net/manual/auxiliary.html";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &, const Core::Molecule &) AVO_OVERRIDE
  {
    // Empty, as we do not write out MOPAC AUX files.
    return false;
  }

private:
  void processLine(std::istream &in);
  void load(Core::SlaterSet* basis);
  std::vector<int> readArrayElements(std::istream &in, unsigned int n);
  std::vector<int> readArrayI(std::istream &in, unsigned int n);
  std::vector<double> readArrayD(std::istream &in, unsigned int n);
  std::vector<int> readArraySym(std::istream &in, unsigned int n);
  std::vector<Vector3> readArrayVec(std::istream &in, unsigned int n);
  bool readOverlapMatrix(std::istream &in, unsigned int n);
  bool readEigenVectors(std::istream &in, unsigned int n);
  bool readDensityMatrix(std::istream &in, unsigned int n);

  int m_electrons;
  std::vector<int> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;  // TODO: support open shell
  std::vector<double> m_MOcoeffs;

  std::vector<int> m_atomIndex;
  std::vector<int> m_atomSym;
  std::vector<int> m_atomNums;
  std::vector<double> m_zeta;
  std::vector<int> m_pqn;
  std::vector<Eigen::Vector3d> m_atomPos;

  Eigen::MatrixXd m_overlap;     /// Overlap matrix
  Eigen::MatrixXd m_eigenVectors;
  Eigen::MatrixXd m_density;     /// Total density matrix
};

} // End namespace QuantumIO
} // End namespace Avogadro

#endif
