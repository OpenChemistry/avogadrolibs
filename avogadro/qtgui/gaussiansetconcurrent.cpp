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
#include <QtCore/QThread>

#include <algorithm>

namespace Avogadro::QtGui {

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
