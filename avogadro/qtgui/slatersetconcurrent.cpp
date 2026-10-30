/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "slatersetconcurrent.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/slaterset.h>
#include <avogadro/core/slatersettools.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/mutex.h>

#include <QtConcurrent/QtConcurrentMap>
#include <QtCore/QSet>

namespace Avogadro::QtGui {

using Core::Cube;
using Core::SlaterSet;
using Core::SlaterSetTools;

struct SlaterShell
{
  SlaterSetTools* tools; // A pointer to the tools, cannot write to member vars
  Cube* tCube;           // The target cube, used to initialise temp cubes too
  unsigned int pos;      // The index of the point to calculate the MO for
  unsigned int state;    // The MO number to calculate
};

namespace {
/// Every live calculator, so that cubes can be protected from deletion while
/// any of them is still writing. Instances are only created and destroyed on
/// the GUI thread, so this needs no locking of its own.
QSet<SlaterSetConcurrent*>& liveCalculations()
{
  static QSet<SlaterSetConcurrent*> instances;
  return instances;
}
} // namespace

SlaterSetConcurrent::SlaterSetConcurrent(QObject* p)
  : QObject(p), m_shells(nullptr), m_set(nullptr), m_tools(nullptr)
{
  liveCalculations().insert(this);
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
}

SlaterSetConcurrent::~SlaterSetConcurrent()
{
  liveCalculations().remove(this);
  cancelAndWait();
  delete m_tools;
}

void SlaterSetConcurrent::setMolecule(Core::Molecule* mol)
{
  if (!mol)
    return;
  // The worker items hold a raw pointer to m_tools, so nothing may replace it
  // while a calculation is still in flight.
  cancelAndWait();

  // Let go of the previous job's basis set first: still holding it would
  // make the mutable access below copy it for nothing.
  m_basisHandle.reset();

  // Setting up a calculation writes into the basis set (initCalculation(),
  // and generateDensityMatrix() for a Gaussian set), so take the mutable
  // one. The molecule gets a private copy if an undo snapshot shares it.
  m_set = dynamic_cast<SlaterSet*>(mol->basisSet());

  delete m_tools;
  m_tools = new SlaterSetTools(mol);

  // The workers read m_set through m_tools on other threads. Hold it for the
  // job, so that if the molecule later detaches from it (a copy, then a
  // write) and the snapshot that ends up with it is freed, it stays alive.
  m_basisHandle = mol->sharedBasisSet();
}

bool SlaterSetConcurrent::calculateMolecularOrbital(Core::Cube* cube,
                                                    unsigned int state)
{
  return setUpCalculation(cube, state, SlaterSetConcurrent::processOrbital);
}

bool SlaterSetConcurrent::calculateElectronDensity(Core::Cube* cube)
{
  return setUpCalculation(cube, 0, SlaterSetConcurrent::processDensity);
}

bool SlaterSetConcurrent::calculateSpinDensity(Core::Cube* cube)
{
  return setUpCalculation(cube, 0, SlaterSetConcurrent::processSpinDensity);
}

void SlaterSetConcurrent::calculationComplete()
{
  // A queued finished() from a cancelled run can arrive after the next
  // calculation has already been set up. Never free that one's work items.
  if (m_future.isRunning())
    return;

  // The job is over. Holding the basis set any longer would make the next
  // mutable access copy it; setMolecule() takes it again for the next job.
  m_basisHandle.reset();

  // (*m_shells)[0].tCube->lock()->unlock();
  delete m_shells;
  m_shells = nullptr;
  emit finished();
}

void SlaterSetConcurrent::cancelAllCalculations()
{
  // Copy, because cancelAndWait() spins the caller's thread and a calculator
  // could be destroyed while we are working through the list.
  const QSet<SlaterSetConcurrent*> instances = liveCalculations();
  for (SlaterSetConcurrent* calculation : instances) {
    if (liveCalculations().contains(calculation))
      calculation->cancelAndWait();
  }
}

void SlaterSetConcurrent::cancelAndWait()
{
  if (m_future.isStarted() && !m_future.isFinished()) {
    m_future.cancel();
    m_future.waitForFinished();
  }
  delete m_shells;
  m_shells = nullptr;
}

bool SlaterSetConcurrent::setUpCalculation(Core::Cube* cube, unsigned int state,
                                           void (*func)(SlaterShell&))
{
  // Without the handle (no setMolecule() since the last job) m_set and
  // m_tools may refer to a basis set that has been freed.
  if (!m_set || !m_tools || !m_basisHandle)
    return false;

  cancelAndWait();

  m_set->initCalculation();

  // Set up the points we want to calculate the density at.
  m_shells = new QVector<SlaterShell>(static_cast<int>(cube->data()->size()));

  for (int i = 0; i < m_shells->size(); ++i) {
    (*m_shells)[i].tools = m_tools;
    (*m_shells)[i].tCube = cube;
    (*m_shells)[i].pos = i;
    (*m_shells)[i].state = state;
  }

  // Lock the cube until we are done.
  // cube->lock()->lock();

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_shells, func);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

void SlaterSetConcurrent::processOrbital(SlaterShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(
    shell.pos, shell.tools->calculateMolecularOrbital(pos, shell.state));
}

void SlaterSetConcurrent::processDensity(SlaterShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos, shell.tools->calculateElectronDensity(pos));
}

void SlaterSetConcurrent::processSpinDensity(SlaterShell& shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos, shell.tools->calculateSpinDensity(pos));
}
} // namespace Avogadro::QtGui
