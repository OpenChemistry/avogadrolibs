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

#include "avogadroioexport.h"

#include <avogadro/core/molecule.h>

#include <string>

namespace Avogadro {
namespace Io {

/*!
 * \class CmlFormat cmlformat.h <avogadro/io/cmlformat.h>
 * \brief Implementation of the Chemical Markup Language format.
 * \author Marcus D. Hanwell
 */

class AVOGADROIO_EXPORT CmlFormat
{
public:
  CmlFormat();
  ~CmlFormat();

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
};

} // end Io namespace
} // end Avogadro namespace

#endif // CMLFORMAT_H
