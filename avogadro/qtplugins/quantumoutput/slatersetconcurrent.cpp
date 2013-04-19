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

#include "slatersetconcurrent.h"

#include <avogadro/core/slaterset.h>
#include <avogadro/core/slatersettools.h>

#include <avogadro/qtgui/cube.h>

#include <QtCore/QReadWriteLock>
#include <QtCore/QtConcurrentMap>

namespace Avogadro {
namespace QtPlugins {

using Core::SlaterSet;
using Core::SlaterSetTools;
using QtGui::Cube;

struct SlaterShell
{
  SlaterSetTools *tools;   // A pointer to the GaussianSet, cannot write to member vars
  Cube *tCube;        // The target cube, used to initialise temp cubes too
  unsigned int pos;   // The index ofposition of the point to calculate the MO for
  unsigned int state; // The MO number to calculate
};

SlaterSetConcurrent::SlaterSetConcurrent(QObject *p) : QObject(p),
  m_shells(NULL), m_set(NULL), m_tools(NULL)
{
}

SlaterSetConcurrent::~SlaterSetConcurrent()
{
  delete m_shells;
}

void SlaterSetConcurrent::setMolecule(Core::Molecule *mol)
{
  if (!mol)
    return;
  m_set = dynamic_cast<SlaterSet *>(mol->basisSet());
  if (m_tools)
    delete m_tools;
  m_tools = new SlaterSetTools(mol);
}

bool SlaterSetConcurrent::calculateMolecularOrbital(QtGui::Cube *cube,
                                                    unsigned int state)
{
  return setUpCalculation(cube, state, SlaterSetConcurrent::processOrbital);
}

bool SlaterSetConcurrent::calculateElectronDensity(QtGui::Cube *cube)
{
  return setUpCalculation(cube, 0, SlaterSetConcurrent::processDensity);
}

bool SlaterSetConcurrent::calculateSpinDensity(QtGui::Cube *cube)
{
  return setUpCalculation(cube, 0, SlaterSetConcurrent::processSpinDensity);
}

void SlaterSetConcurrent::calculationComplete()
{
  disconnect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  (*m_shells)[0].tCube->lock()->unlock();
  delete m_shells;
  m_shells = 0;
  emit finished();
}

bool SlaterSetConcurrent::setUpCalculation(QtGui::Cube *cube,
                                             unsigned int state,
                                             void (*func)(SlaterShell &))
{
  if (!m_set || !m_tools)
    return false;

  m_set->initCalculation();

  // Set up the points we want to calculate the density at.
  m_shells = new QVector<SlaterShell>(cube->data()->size());

  for (int i = 0; i < m_shells->size(); ++i) {
    (*m_shells)[i].tools = m_tools;
    (*m_shells)[i].tCube = cube;
    (*m_shells)[i].pos = i;
    (*m_shells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_shells, func);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

void SlaterSetConcurrent::processOrbital(SlaterShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateMolecularOrbital(pos,
                                                               shell.state));
}

void SlaterSetConcurrent::processDensity(SlaterShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateElectronDensity(pos));
}

void SlaterSetConcurrent::processSpinDensity(SlaterShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateSpinDensity(pos));
}

}
}
