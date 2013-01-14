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

#ifndef AVOGADRO_QUANTUMIO_BASISSETLOADER_H
#define AVOGADRO_QUANTUMIO_BASISSETLOADER_H

#include "avogadroquantumioexport.h"

// Forward declarations
class QString;

namespace Avogadro {

namespace Quantum {
class BasisSet;
}

namespace QuantumIO {

using Quantum::BasisSet;

/**
 * @class BasisSetLoader basissetloader.h <avogadro/quantumio/basissetloader.h>
 * @brief BasisSetLoader chooses the correct parser, loads the file and returns
 * a basis set of the correct type.
 * @author Marcus D. Hanwell
 *
 * This class is very much subject to change. It removes the logic from the
 * individual classes, and takes care of choosing the correct parser before
 * loading a basis set and returning an object containing this data.
 */

class AVOGADROQUANTUMIO_EXPORT BasisSetLoader
{
public:
  /**
   * Try to match the basis set to the supplied file path. This function will
   * search for a matching basis set file in the same directory.
   *
   * @return Proposed file that would be loaded. Empty if no file found.
   */
  static QString MatchBasisSet(const QString& filename);

  /**
   * Try to match the basis set to the supplied file path. This function will
   * search for a matching basis set file in the same directory.
   *
   * @param basisName char array that is overwritten with the corresponding
   * basis set file for @a filename. Ensure that this array is long enough to
   * contain the basis set name and path. Zero if no match found.
   */
  static void MatchBasisSet(const char *filename, char *basisName );

  /**
   * Load the supplied output file. The filename should be a valid quantum
   * output file.
   *
   * @return A BasisSet object populated with data file the file. Null on error.
   */
  static BasisSet * LoadBasisSet(const QString& filename);

  /**
   * Load the supplied output file. The filename should be a valid quantum
   * output file.
   *
   * @return A BasisSet object populated with data file the file. Null on error.
   */
  static BasisSet * LoadBasisSet(const char *filename);
};

} // End namespace
}

#endif
