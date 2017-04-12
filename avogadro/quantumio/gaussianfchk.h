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

#ifndef AVOGADRO_QUANTUMIO_GAUSSIANFCHK_H
#define AVOGADRO_QUANTUMIO_GAUSSIANFCHK_H

#include "avogadroquantumioexport.h"
#include <avogadro/core/gaussianset.h>
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT GaussianFchk : public Io::FileFormat
{
public:
  GaussianFchk();
  ~GaussianFchk() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new GaussianFchk; }
  std::string identifier() const override { return "Avogadro: FCHK"; }
  std::string name() const override { return "Gaussian FCHK"; }
  std::string description() const override
  {
    return "Guassian formatted checkpoint reader.";
  }

  std::string specificationUrl() const override
  {
    return "http://www.gaussian.com/g_tech/g_ur/f_formchk.htm";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream&, const Core::Molecule&) override
  {
    // Empty, as we do not write out Gaussian FCHK files.
    return false;
  }

  void outputAll();

private:
  void processLine(std::istream& in);
  void load(Core::GaussianSet* basis);
  std::vector<int> readArrayI(std::istream& in, unsigned int n);
  std::vector<double> readArrayD(std::istream& in, unsigned int n,
                                 int width = 0);
  bool readDensityMatrix(std::istream& in, unsigned int n, int width = 0);
  bool readSpinDensityMatrix(std::istream& in, unsigned int n, int width = 0);

  /**
   * Use either m_electrons, or m_electronsAlpha and m_electronsBeta.
   * This then carries through to the energy, coefficients etc.
   */
  int m_electrons;
  int m_electronsAlpha;
  int m_electronsBeta;
  unsigned int m_numBasisFunctions;
  std::vector<int> m_aNums;
  std::vector<double> m_aPos;
  std::vector<int> m_shellTypes;
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
  MatrixX m_density;     /// Total density matrix
  MatrixX m_spinDensity; /// Spin density matrix
  Core::ScfType m_scftype;
};
}
}

#endif
