/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gaussiansetconcurrent.h"

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/mutex.h>

#include <avogadro/core/cube.h>

#include <QtConcurrent/QtConcurrentMap>
#include <QtCore/QSet>
#include <QtCore/QThread>

#include <algorithm>

namespace Avogadro::QtGui {

using Core::BasisSet;
using Core::Cube;
using Core::GaussianSet;
using Core::GaussianSetTools;

// One x-slab work item. Threads operate on non-overlapping i ranges so
// writes to the cube buffer never conflict (cube layout is i-major).
struct GaussianShell
{
  GaussianSetTools* tools;
  Cube* tCube;
  int iStart;
  int iEnd;
  unsigned int state; // MO index — only used by the orbital path
};

namespace {
/// Every live calculator, so that cubes can be protected from deletion while
/// any of them is still writing. Instances are only created and destroyed on
/// the GUI thread, so this needs no locking of its own.
QSet<GaussianSetConcurrent*>& liveCalculations()
{
  static QSet<GaussianSetConcurrent*> instances;
  return instances;
}
} // namespace

GaussianSetConcurrent::GaussianSetConcurrent(QObject* p)
  : QObject(p), m_gaussianShells(nullptr), m_set(nullptr), m_tools(nullptr)
{
  liveCalculations().insert(this);
  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
}

GaussianSetConcurrent::~GaussianSetConcurrent()
{
  liveCalculations().remove(this);
  cancelAndWait();
  delete m_tools;
}

void GaussianSetConcurrent::setMolecule(Core::Molecule* mol)
{
  if (!mol)
    return;
  // The worker items hold a raw pointer to m_tools, so nothing may replace it
  // while a calculation is still in flight.
  cancelAndWait();

  m_set = dynamic_cast<GaussianSet*>(mol->basisSet());

  delete m_tools;
  m_tools = new GaussianSetTools(mol);
}

bool GaussianSetConcurrent::calculateMolecularOrbital(Core::Cube* cube,
                                                      unsigned int state,
                                                      bool beta)
{
  if (!m_tools)
    return false;

  // setElectronType() mutates the tools the running workers hold a pointer to,
  // so the previous calculation has to be stopped before touching it -
  // setUpCalculation() below cancels too late for this.
  cancelAndWait();

  // We can do some initial set up of the tools here to set electron type.
  if (!beta)
    m_tools->setElectronType(BasisSet::Alpha);
  else
    m_tools->setElectronType(BasisSet::Beta);

  return setUpCalculation(cube, state, GaussianSetConcurrent::processOrbital);
}

bool GaussianSetConcurrent::calculateElectronDensity(Core::Cube* cube)
{
  if (!m_set)
    return false;

  // generateDensityMatrix() mutates the set the running workers read through
  // m_tools, so it has the same ordering requirement as the orbital path.
  cancelAndWait();

  const MatrixX& matrix = m_set->densityMatrix();
  if (matrix.rows() == 0 || matrix.cols() == 0) {
    // we don't have a density matrix, so calculate one
    m_set->generateDensityMatrix();
  }

  return setUpCalculation(cube, 0, GaussianSetConcurrent::processDensity);
}

bool GaussianSetConcurrent::calculateSpinDensity(Core::Cube* cube)
{
  return setUpCalculation(cube, 0, GaussianSetConcurrent::processSpinDensity);
}

void GaussianSetConcurrent::calculationComplete()
{
  // A queued finished() from a cancelled run can arrive after the next
  // calculation has already been set up. Never free that one's work items.
  if (m_future.isRunning())
    return;

  delete m_gaussianShells;
  m_gaussianShells = nullptr;
  emit finished();
}

void GaussianSetConcurrent::cancelAllCalculations()
{
  // Copy, because cancelAndWait() spins the caller's thread and a calculator
  // could be destroyed while we are working through the list.
  const QSet<GaussianSetConcurrent*> instances = liveCalculations();
  for (GaussianSetConcurrent* calculation : instances) {
    if (liveCalculations().contains(calculation))
      calculation->cancelAndWait();
  }
}

void GaussianSetConcurrent::cancelAndWait()
{
  if (m_future.isStarted() && !m_future.isFinished()) {
    m_future.cancel();
    m_future.waitForFinished();
  }
  delete m_gaussianShells;
  m_gaussianShells = nullptr;
}

bool GaussianSetConcurrent::setUpCalculation(Core::Cube* cube,
                                             unsigned int state,
                                             void (*func)(GaussianShell&))
{
  if (!m_set || !m_tools)
    return false;

  cancelAndWait();

  m_set->initCalculation();

  // Partition nx into x-slabs, one per available core (capped at nx).
  // x-slabs map to contiguous m_data ranges (i is slowest-varying), so threads
  // never share a cache line and never need locking.
  const int nx = cube->nx();
  int nSlabs = std::max(1, QThread::idealThreadCount());
  nSlabs = std::min(nSlabs, std::max(1, nx));

  m_gaussianShells = new QVector<GaussianShell>(nSlabs);
  for (int s = 0; s < nSlabs; ++s) {
    int iStart = s * nx / nSlabs;
    int iEnd = (s + 1) * nx / nSlabs;
    (*m_gaussianShells)[s] = { m_tools, cube, iStart, iEnd, state };
  }

  // Map the work items across the QtConcurrent thread pool.
  m_future = QtConcurrent::map(*m_gaussianShells, func);
  m_watcher.setFuture(m_future);

  return true;
}

void GaussianSetConcurrent::processOrbital(GaussianShell& shell)
{
  shell.tools->calculateMolecularOrbitalSlab(
    *shell.tCube, static_cast<int>(shell.state), shell.iStart, shell.iEnd);
}

void GaussianSetConcurrent::processDensity(GaussianShell& shell)
{
  shell.tools->calculateElectronDensitySlab(*shell.tCube, shell.iStart,
                                            shell.iEnd);
}

void GaussianSetConcurrent::processSpinDensity(GaussianShell& shell)
{
  shell.tools->calculateSpinDensitySlab(*shell.tCube, shell.iStart, shell.iEnd);
}
} // namespace Avogadro::QtGui
