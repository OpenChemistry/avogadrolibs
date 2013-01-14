/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011 David C. Lonie
  Copyright 2012-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "basisset.h"

#include <QtCore/QFutureWatcher>

namespace Avogadro {
namespace Quantum {

bool BasisSet::blockingCalculateCubeMO(Cube *cube, unsigned int mo)
{
  if (!this->calculateCubeMO(cube, mo))
    return false;
  this->watcher().waitForFinished();
  return true;
}

bool BasisSet::blockingCalculateCubeAlphaMO(Cube *cube, unsigned int mo)
{
  if (!this->calculateCubeAlphaMO(cube, mo))
    return false;
  this->watcher().waitForFinished();
  return true;
}

bool BasisSet::blockingCalculateCubeBetaMO(Cube *cube, unsigned int mo)
{
  if (!this->calculateCubeBetaMO(cube, mo))
    return false;
  this->watcher().waitForFinished();
  return true;
}

bool BasisSet::blockingCalculateCubeDensity(Cube *cube)
{
  if (!this->calculateCubeDensity(cube))
    return false;
  this->watcher().waitForFinished();
  return true;
}

bool BasisSet::blockingCalculateCubeSpinDensity(Cube *cube)
{
  if (!this->calculateCubeSpinDensity(cube))
    return false;
  this->watcher().waitForFinished();
  return true;
}

} // End namespace Quantum
} // End namespace Avogadro
