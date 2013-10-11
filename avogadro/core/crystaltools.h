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

#ifndef AVOGADRO_CORE_CRYSTALTOOLS_H
#define AVOGADRO_CORE_CRYSTALTOOLS_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"
#include "matrix.h"
#include "vector.h"

#include <vector>

namespace Avogadro {
namespace Core {
class Molecule;

class AVOGADROCORE_EXPORT CrystalTools
{
public:
  enum Option {
    None = 0x0,
    TransformAtoms = 0x1
  };
  typedef int Options;

  static bool wrapAtomsToUnitCell(Molecule &molecule);

  // This function will rotate the input cell matrix so that v1 is along the
  // x-axis, and v2 is in the xy-plane. It does not use trig functions or
  // the cell parameters, since such implementations are fragile and cannot
  // handle negative cell angles. The derivation of this algorithm can be found
  // at http://xtalopt.openmolecules.net/misc/rotateToStdOrientation.pdf
  static bool rotateToStandardOrientation(Molecule &molecule,
                                          Options opts = None);

  static bool setVolume(Molecule &molecule, Real newVolume,
                        Options opts = None);

  // Implements the niggli reduction algorithm detailed in:
  // Grosse-Kunstleve RW, Sauter NK, Adams PD. Numerically stable
  // algorithms for the computation of reduced unit cells. Acta
  // Crystallographica Section A Foundations of
  // Crystallography. 2003;60(1):1-6.
  static bool niggliReduce(Molecule &molecule, Options opts = None);

  static bool setCellMatrix(Molecule &molecule, const Matrix3 &newCellRowMatrix,
                            Options opt = None);

  static bool fractionalCoordinates(const Molecule &molecule,
                                    std::vector<Vector3> &coords);

  static bool setFractionalCoordinates(Molecule &molecule,
                                       const std::vector<Vector3> &coords);

private:
  CrystalTools(); // not implemented
  ~CrystalTools(); // not implemented
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_CRYSTALTOOLS_H
