/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2008 Marcus D. Hanwell
  Copyright 2010-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_GAMESSUS_H
#define AVOGADRO_QUANTUMIO_GAMESSUS_H

#include <QtCore/QIODevice>
#include <Eigen/Core>
#include <vector>

#include <avogadro/quantum/gaussianset.h>

class QString;

namespace Avogadro {
namespace QuantumIO {

using Quantum::GaussianSet;
using Quantum::orbital;

class GAMESSUSOutput
{
  // Parsing mode: section of the file currently being parsed
  enum mode { NotParsing, Atoms, GTO, MO };
  enum scfMode { alpha, beta, doubly };
  enum scf  { rhf, uhf, rohf, Unknown };

public:
  GAMESSUSOutput(const QString &filename, GaussianSet *basis);
  ~GAMESSUSOutput();
  void outputAll();

private:
  QIODevice *m_in;
  void processLine(GaussianSet *basis);
  void load(GaussianSet *basis);

  double m_coordFactor;
  mode m_currentMode;
  scfMode m_currentScfMode;
  int m_electrons;
  int m_electronsA;
  int m_electronsB;
  int m_currentAtom;
  scf m_scftype;
  unsigned int m_numBasisFunctions;
  std::vector<orbital> m_shellTypes;
  std::vector<int> m_shellNums;
  std::vector<int> m_shelltoAtom;
  std::vector<double> m_a;
  std::vector<double> m_c;
  std::vector<double> m_csp;
  std::vector<double> m_orbitalEnergy;
  std::vector<double> m_alphaOrbitalEnergy;
  std::vector<double> m_betaOrbitalEnergy;
  std::vector<double> m_MOcoeffs;
  std::vector<double> m_alphaMOcoeffs;
  std::vector<double> m_betaMOcoeffs;

  Eigen::MatrixXd m_density;     /// Total density matrix
  void generateDensity();
};

} // End namespace
}

#endif
