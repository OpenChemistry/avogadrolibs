/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_IO_CMLFORMAT_H
#define AVOGADRO_IO_CMLFORMAT_H

#include "avogadroio.h"

#include <avogadro/core/molecule.h>

#include <string>
#include <vector>

namespace Avogadro {
namespace Io {

class AVOGADROIO_EXPORT CmlFormat
{
public:
  CmlFormat();
  ~CmlFormat();

  bool test() { return true; }

  bool readFile(const std::string &fileName);

  bool writeFile(const std::string &fileName);

  Core::Molecule * molecule(size_t index = 0);

protected:
  std::vector<Core::Molecule *> m_molecules;
};

} // end Io namespace
} // end Avogadro namespace

#endif // CMLFORMAT_H
