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

#ifndef AVOGADRO_IO_CJSONFORMAT_H
#define AVOGADRO_IO_CJSONFORMAT_H

#include "avogadroioexport.h"

#include <string>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace Io {

class AVOGADROIO_EXPORT CjsonFormat
{
public:
  CjsonFormat();
  ~CjsonFormat();

  bool readFile(const std::string &fileName, Core::Molecule &molecule);

  bool writeFile(const std::string &fileName, const Core::Molecule &molecule);

};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_CJSONFORMAT_H
