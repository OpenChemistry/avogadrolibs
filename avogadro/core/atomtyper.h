/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_ATOMTYPER_H
#define AVOGADRO_CORE_ATOMTYPER_H

#include "avogadrocore.h"

#include <avogadro/core/array.h>

#include <string>

namespace Avogadro {
namespace Core {
class Atom;
class Molecule;

/**
 * @class AtomTyper atomtyper.h <avogadro/core/atomtyper.h>
 * @brief The AtomTyper class provides a base interface for generating a list of
 * strings describing the atoms in a molecule.
 */
class AVOGADROCORE_EXPORT AtomTyper
{
public:
  explicit AtomTyper(const Molecule *mol = NULL);
  virtual ~AtomTyper();

  /**
   * @param mol The molecule with atoms to type.
   */
  void setMolecule(const Molecule *mol);

  /**
   * Iterate through the molecule and generate type descriptions for each atom.
   * The results can be obtained by calling types().
   */
  void run();

  /**
   * @return An Array of strings. There will be one string for each atom of the
   * input Molecule, and they are ordered by the corresponding atom's index.
   */
  Array<std::string> types() const;

protected:
  /**
   * Perform any setup needed that needs to be done prior to calling type(). The
   * base implementation of this function clears m_types and reserves enough
   * room for the current Molecule.
   */
  virtual void initialize();

  /**
   * Determines the type of the atom.
   * @param atom The atom to type.
   * @return The type of @a atom.
   */
  virtual std::string type(const Atom &atom) = 0;

  /**
   * Perform any cleanup/post-processing after type() has been called for each
   * atom.
   */
  virtual void finalize();

  /** The molecule on which to operate. */
  const Molecule *m_molecule;

  /** The array of types to be populated. */
  Array<std::string> m_types;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ATOMTYPER_H
