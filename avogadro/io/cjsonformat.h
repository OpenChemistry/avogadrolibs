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

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/*!
 * \class CjsonFormat cjsonformat.h <avogadro/io/cjsonformat.h>
 * \brief Implementation of the Chemical JSON format.
 * \author Marcus D. Hanwell
 */

class AVOGADROIO_EXPORT CjsonFormat : public FileFormat
{
public:
  CjsonFormat();
  ~CjsonFormat();

  FileFormat * createInstance() { return new CjsonFormat; }
  std::string identifier() const { return "CJSON"; }
  std::string name() const { return "Chemical JSON"; }
  std::string description() const { return "TODO: Describe the format."; }

  std::string specificationURL() const
  {
    return "http://wiki.openchemistry.org/Chemical_JSON";
  }

  std::vector<std::string> fileExtensions() const;
  std::vector<std::string> mimeTypes() const;

  bool read(std::istream &in, Core::Molecule &molecule);
  bool write(std::ostream &out, const Core::Molecule &molecule);
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_CJSONFORMAT_H
