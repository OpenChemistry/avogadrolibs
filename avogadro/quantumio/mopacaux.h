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

#include <QtCore/QTextStream>
#include <Eigen/Core>
#include <vector>

class QString;

namespace Avogadro {

namespace Quantum {
class SlaterSet;
}

namespace QuantumIO {

using Quantum::SlaterSet;

class MopacAux
{
public:
  MopacAux(QString filename, SlaterSet *basis);
  ~MopacAux();
  void outputAll();

private:
  QTextStream m_in;
  void processLine();
  void load(SlaterSet* basis);
  std::vector<int> readArrayI(unsigned int n);
  std::vector<double> readArrayD(unsigned int n);
  std::vector<int> readArraySym(unsigned int n);
  std::vector<Eigen::Vector3d> readArrayVec(unsigned int n);
  bool readOverlapMatrix(unsigned int n);
  bool readEigenVectors(unsigned int n);
  bool readDensityMatrix(unsigned int n);

  int m_electrons;
  std::vector<int> m_aNums;
  std::vector<double> m_aPos;
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

  Eigen::MatrixXd m_overlap;     /// Overlap matrix
  Eigen::MatrixXd m_eigenVectors;
  Eigen::MatrixXd m_density;     /// Total density matrix
};

} // End namespace QuantumIO
} // End namespace Avogadro

#endif
