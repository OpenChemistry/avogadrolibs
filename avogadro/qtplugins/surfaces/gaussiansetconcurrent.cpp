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

#include "gaussiansetconcurrent.h"

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/mutex.h>

#include <avogadro/core/cube.h>

#include <QtConcurrent/QtConcurrentMap>

namespace Avogadro {
namespace QtPlugins {

using Core::BasisSet;
using Core::Cube;
using Core::GaussianSet;
using Core::GaussianSetTools;
using Core::Molecule;

template <typename Derived>
class BasisSetConcurrent
{
  void setMolecule(Molecule* mol)
  {
    static_cast<Derived*>(this)->setMolecule(mol);
  }
};

struct GaussianShell
{
  GaussianSetTools* tools; // A pointer to the tools, can't write to member vars
  Cube* tCube;             // The target cube, used to initialise temp cubes too
  unsigned int pos;        // The index of the point to calculate the MO for
  unsigned int state;      // The MO number to calculate
};

GaussianSetConcurrent::GaussianSetConcurrent(QObject* p)
  : QObject(p), m_gaussianShells(nullptr), m_set(nullptr), m_tools(nullptr)
{
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
}

GaussianSetConcurrent::~GaussianSetConcurrent()
{
  delete m_gaussianShells;
}

void GaussianSetConcurrent::setMolecule(Core::Molecule* mol)
{
  if (!mol)
    return;
  m_set = dynamic_cast<GaussianSet*>(mol->basisSet());
  if (m_tools)
    delete m_tools;
  m_tools = new GaussianSetTools(mol);
}

bool GaussianSetConcurrent::calculateMolecularOrbital(Core::Cube* cube,
                                                      unsigned int state,
                                                      bool beta)
{
  // We can do some initial set up of the tools here to set electron type.
  if (!beta)
    m_tools->setElectronType(BasisSet::Alpha);
  else
    m_tools->setElectronType(BasisSet::Beta);

  return setUpCalculation(cube, state, GaussianSetConcurrent::processOrbital);
}

bool GaussianSetConcurrent::calculateElectronDensity(Core::Cube* cube)
{
  return setUpCalculation(cube, 0, GaussianSetConcurrent::processDensity);
}

bool GaussianSetConcurrent::calculateSpinDensity(Core::Cube* cube)
{
  return setUpCalculation(cube, 0, GaussianSetConcurrent::processSpinDensity);
}

void GaussianSetConcurrent::calculationComplete()
{
  (*m_gaussianShells)[0].tCube->lock()->unlock();
  delete m_gaussianShells;
  m_gaussianShells = nullptr;
  emit finished();
}

bool GaussianSetConcurrent::setUpCalculation(Core::Cube* cube,
                                             unsigned int state,
                                             void (*func)(GaussianShell&))
{
  if (!m_set || !m_tools)
    return false;

  m_set->initCalculation();

  // Set up the points we want to calculate the density at.
  m_gaussianShells =
    new QVector<GaussianShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].tools = m_tools;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
    (*m_gaussianShells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lock();

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, func);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

void GaussianSetConcurrent::processOrbital(GaussianShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(
    shell.pos, shell.tools->calculateMolecularOrbital(pos, shell.state));
}

void GaussianSetConcurrent::processDensity(GaussianShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos, shell.tools->calculateElectronDensity(pos));
}

void GaussianSetConcurrent::processSpinDensity(GaussianShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos, shell.tools->calculateSpinDensity(pos));
}
}
}
