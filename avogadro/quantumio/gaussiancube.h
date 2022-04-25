/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Barry E. Moore II

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QUANTUMIO_GAUSSIANCUBE_H
#define AVOGADRO_QUANTUMIO_GAUSSIANCUBE_H

#include "avogadroquantumioexport.h"
#include <avogadro/io/fileformat.h>

#include <vector>

namespace Avogadro {
namespace QuantumIO {

class AVOGADROQUANTUMIO_EXPORT GaussianCube : public Io::FileFormat
{
public:
  GaussianCube();
  ~GaussianCube() override;

  Operations supportedOperations() const override
  {
    return Read | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new GaussianCube; }
  std::string identifier() const override { return "Avogadro: Gaussian Cube"; }
  std::string name() const override { return "Gaussian"; }
  std::string description() const override
  {
    return "Gaussian cube file format.";
  }

  std::string specificationUrl() const override
  {
    return "https://gaussian.com/cubegen/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;

private:
  void outputAll();
}; // End GaussianCube

} // End QuantumIO namespace
} // End Avogadro namespace

#endif
