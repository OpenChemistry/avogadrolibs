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

namespace Json {
class Value;
}

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace Io {

/*!
 * \class CjsonFormat cjsonformat.h <avogadro/io/cjsonformat.h>
 * \brief Implementation of the Chemical JSON format.
 * \author Marcus D. Hanwell
 */

class AVOGADROIO_EXPORT CjsonFormat
{
public:
  CjsonFormat();
  ~CjsonFormat();

  /*!
   * \brief Read the given \p fileName and load it into \p molecule.
   * \param fileName The full path to the file to be read in.
   * \param molecule The molecule the data will be read into.
   * \return True on success, false on failure.
   */
  bool readFile(const std::string &fileName, Core::Molecule &molecule);

  /*!
   * \brief Write to the given \p fileName the contents of \p molecule.
   * \param fileName The full path to the file to be written.
   * \param molecule The contents of this molecule will be written to the file.
   * \return True on success, false on failure.
   */
  bool writeFile(const std::string &fileName, const Core::Molecule &molecule);

  /*!
   * \brief Read the given \p cJson string and load it into \p molecule.
   * \param cJson A std::string to overwrite.
   * \param molecule The molecule the data will be read into.
   * \return True on success, false on failure.
   */
  bool readString(const std::string &cJson, Core::Molecule &molecule);

  /*!
   * \brief Write to the given \p cJson string the contents of \p molecule.
   * \param cJson A std::string to overwrite.
   * \param molecule The contents of this molecule will be written to the file.
   * \return True on success, false on failure.
   */
  bool writeString(std::string &cJson, const Core::Molecule &molecule);

private:
  bool readJson(const Json::Value &json, Core::Molecule &molecule);
  bool writeJson(Json::Value &json, const Core::Molecule &molecule);

};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_CJSONFORMAT_H
