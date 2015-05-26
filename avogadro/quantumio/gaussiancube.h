/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Barry E. Moore II
  Copyright 2013 Kitware, Inc.

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
  ~GaussianCube() AVO_OVERRIDE;

  Operations supportedOperations() const AVO_OVERRIDE
  {
    return Read | File | Stream | String;
  }

  FileFormat * newInstance() const AVO_OVERRIDE { return new GaussianCube; }
  std::string identifier() const AVO_OVERRIDE { return "Avogadro: GaussianCube"; }
  std::string name() const AVO_OVERRIDE { return "Gaussian"; }
  std::string description() const AVO_OVERRIDE
  {
    return "Gaussian cube file format.";
  }

  std::string specificationUrl() const AVO_OVERRIDE
  {
    return "http://www.gaussian.com/g_tech/g_ur/u_cubegen.htm";
  }

  std::vector<std::string> fileExtensions() const AVO_OVERRIDE;
  std::vector<std::string> mimeTypes() const AVO_OVERRIDE;

  bool read(std::istream &in, Core::Molecule &molecule) AVO_OVERRIDE;
  bool write(std::ostream &out, const Core::Molecule &molecule) AVO_OVERRIDE;

private:
  void outputAll();
}; // End GaussianCube

} // End QuantumIO namespace
} // End Avogadro namespace

#endif
