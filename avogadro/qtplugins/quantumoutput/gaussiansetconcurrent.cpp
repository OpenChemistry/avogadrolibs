#include "gaussiansetconcurrent.h"

#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>

#include <avogadro/qtgui/cube.h>

#include <QtCore/QReadWriteLock>
#include <QtCore/QtConcurrentMap>

namespace Avogadro {
namespace QtPlugins {

using Core::GaussianSet;
using Core::GaussianSetTools;
using QtGui::Cube;

struct GaussianShell
{
  GaussianSetTools *tools;   // A pointer to the GaussianSet, cannot write to member vars
  Cube *tCube;        // The target cube, used to initialise temp cubes too
  unsigned int pos;   // The index ofposition of the point to calculate the MO for
  unsigned int state; // The MO number to calculate
};


GaussianSetConcurrent::GaussianSetConcurrent(QObject *p) : QObject(p),
  m_gaussianShells(NULL), m_set(NULL), m_tools(NULL)
{
}

GaussianSetConcurrent::~GaussianSetConcurrent()
{
  delete m_gaussianShells;
}

void GaussianSetConcurrent::setMolecule(Core::Molecule *mol)
{
  if (!mol)
    return;
  m_set = dynamic_cast<GaussianSet *>(mol->basisSet());
  if (m_tools)
    delete m_tools;
  m_tools = new GaussianSetTools(mol);
}

bool GaussianSetConcurrent::calculateMolecularOrbital(QtGui::Cube *cube,
                                                      unsigned int state)
{
  return setUpCalculation(cube, state, GaussianSetConcurrent::processOrbital);
}

bool GaussianSetConcurrent::calculateElectronDensity(QtGui::Cube *cube)
{
  return setUpCalculation(cube, 0, GaussianSetConcurrent::processDensity);
}

bool GaussianSetConcurrent::calculateSpinDensity(QtGui::Cube *cube)
{
  return setUpCalculation(cube, 0, GaussianSetConcurrent::processSpinDensity);
}

void GaussianSetConcurrent::calculationComplete()
{
  disconnect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));
  (*m_gaussianShells)[0].tCube->lock()->unlock();
  delete m_gaussianShells;
  m_gaussianShells = 0;
  emit finished();
}

bool GaussianSetConcurrent::setUpCalculation(QtGui::Cube *cube,
                                             unsigned int state,
                                             void (*func)(GaussianShell &))
{
  if (!m_set || !m_tools)
    return false;

  m_set->initCalculation();

  // Set up the points we want to calculate the density at.
  m_gaussianShells = new QVector<GaussianShell>(cube->data()->size());

  for (int i = 0; i < m_gaussianShells->size(); ++i) {
    (*m_gaussianShells)[i].tools = m_tools;
    (*m_gaussianShells)[i].tCube = cube;
    (*m_gaussianShells)[i].pos = i;
    (*m_gaussianShells)[i].state = state;
  }

  // Lock the cube until we are done.
  cube->lock()->lockForWrite();

  // Watch for the future
  connect(&m_watcher, SIGNAL(finished()), this, SLOT(calculationComplete()));

  // The main part of the mapped reduced function...
  m_future = QtConcurrent::map(*m_gaussianShells, func);
  // Connect our watcher to our future
  m_watcher.setFuture(m_future);

  return true;
}

void GaussianSetConcurrent::processOrbital(GaussianShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateMolecularOrbital(pos,
                                                               shell.state));
}

void GaussianSetConcurrent::processDensity(GaussianShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateElectronDensity(pos));
}

void GaussianSetConcurrent::processSpinDensity(GaussianShell &shell)
{
  Vector3 pos = shell.tCube->position(shell.pos);
  shell.tCube->setValue(shell.pos,
                        shell.tools->calculateSpinDensity(pos));
}

}
}
