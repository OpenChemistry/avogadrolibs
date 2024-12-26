/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orbitals.h"
#include "orbitalwidget.h"

#include <avogadro/core/array.h>
#include <avogadro/core/basisset.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/gaussiansetconcurrent.h>
#include <avogadro/qtgui/meshgenerator.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/slatersetconcurrent.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

namespace Avogadro::QtPlugins {

const double cubePadding = 2.5;
const int smoothingPasses = 1;

Orbitals::Orbitals(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_action(new QAction(this)), m_runningMutex(new QMutex)
{
  m_action->setEnabled(false);
  m_action->setText(tr("Molecular Orbitals…"));
  connect(m_action, SIGNAL(triggered()), SLOT(openDialog()));
}

Orbitals::~Orbitals() {}

QList<QAction*> Orbitals::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList Orbitals::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analysis");
  return path;
}

void Orbitals::setMolecule(QtGui::Molecule* mol)
{
  if (mol == nullptr)
    return;

  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  m_molecule = mol;
  // check if it has basis set data
  bool hasOrbitals = (m_molecule->basisSet() != nullptr);

  if (hasOrbitals)
    m_action->setEnabled(true);
  else {
    m_action->setEnabled(false);
    if (m_dialog)
      m_dialog->hide();
  }

  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));

  // Stuff we manage that will not be valid any longer
  m_queue.clear();
  m_currentRunningCalculation = -1;

  if (m_basis) {
    delete m_basis;
    m_basis = nullptr;
  }

  loadBasis();

  if (!m_basis || m_basis->electronCount() == 0)
    return; // no electrons, no orbitals

  loadOrbitals();
  precalculateOrbitals();
}

void Orbitals::loadBasis()
{
  if (m_molecule != nullptr) {
    m_basis = m_molecule->basisSet();
  }
}

void Orbitals::loadOrbitals()
{
  if (m_basis == nullptr || m_molecule == nullptr)
    return;

  if (!m_dialog) {
    m_dialog = new OrbitalWidget(qobject_cast<QWidget*>(parent()), Qt::Window);
    connect(m_dialog, SIGNAL(orbitalSelected(unsigned int)), this,
            SLOT(renderOrbital(unsigned int)));
    connect(m_dialog, SIGNAL(renderRequested(unsigned int, double)), this,
            SLOT(calculateOrbitalFromWidget(unsigned int, double)));
    connect(m_dialog, SIGNAL(calculateAll()), this,
            SLOT(precalculateOrbitals()));
  }

  m_dialog->fillTable(m_basis);
}

void Orbitals::moleculeChanged(unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  bool isEnabled = m_action->isEnabled();
  bool hasOrbitals = (m_molecule->basisSet() != nullptr);

  if (isEnabled != hasOrbitals) {
    m_action->setEnabled(hasOrbitals);
    if (hasOrbitals)
      openDialog();
  }
}

void Orbitals::openDialog()
{
  if (!m_dialog) {
    m_dialog = new OrbitalWidget(qobject_cast<QWidget*>(parent()), Qt::Window);
    connect(m_dialog, SIGNAL(orbitalSelected(unsigned int)), this,
            SLOT(renderOrbital(unsigned int)));
    connect(m_dialog, SIGNAL(renderRequested(unsigned int, double)), this,
            SLOT(calculateOrbitalFromWidget(unsigned int, double)));
    connect(m_dialog, SIGNAL(calculateAll()), this,
            SLOT(precalculateOrbitals()));
  }

  m_dialog->show();
  m_dialog->raise();
}

void Orbitals::calculateOrbitalFromWidget(unsigned int orbital,
                                          double resolution)
{
  m_updateMesh = true;
  addCalculationToQueue(orbital, resolution, m_dialog->isovalue(), 0);
  checkQueue();
}

void Orbitals::precalculateOrbitals()
{
  if (m_basis == nullptr)
    return;

  m_updateMesh = false;

  // Determine HOMO
  unsigned int homo = m_basis->homo();

  // Initialize prioritizer at HOMO's index
  int priority = homo;

  // Loop through all MOs, submitting calculations with increasing
  // priority until HOMO is reached, submit both HOMO and LUMO at
  // priority=1, then start increasing for orbitals above LUMO.
  // E.g,
  // .... HOMO-2 HOMO-1 HOMO LUMO LUMO+1 LUMO+2 ... << orbitals
  // ....   3      2     1    1     2      3    ... << priorities

  // Determine range of precalculated orbitals
  int startIndex =
    (m_dialog->precalcLimit()) ? homo - (m_dialog->precalcRange() / 2) : 0;
  if (startIndex < 0) {
    startIndex = 0;
  }
  int endIndex = (m_dialog->precalcLimit())
                   ? homo + (m_dialog->precalcRange() / 2) - 1
                   : m_basis->molecularOrbitalCount();
  if (endIndex > m_basis->molecularOrbitalCount() - 1) {
    endIndex = m_basis->molecularOrbitalCount() - 1;
  }

  for (unsigned int i = startIndex; i <= endIndex; i++) {
#ifndef NDEBUG
    qDebug() << " precalculate " << i << " priority " << priority;
#endif
    addCalculationToQueue(
      i, // orbital
      OrbitalWidget::OrbitalQualityToDouble(m_dialog->defaultQuality()),
      m_dialog->isovalue(), priority);

    // Update priority. Stays the same when i = homo.
    if (i + 1 < homo)
      priority--;
    else if (i + 1 > homo)
      priority++;
  }
  checkQueue();
}

void Orbitals::addCalculationToQueue(unsigned int orbital, double resolution,
                                     double isovalue, unsigned int priority)
{
  // Create new queue entry
  calcInfo newCalc;
  newCalc.orbital = orbital;
  newCalc.resolution = resolution;
  newCalc.isovalue = isovalue;
  newCalc.priority = priority;
  newCalc.state = NotStarted;

  // Add new calculation
  m_queue.append(newCalc);

  // Set progress to show 0%
  m_dialog->calculationQueued(newCalc.orbital);
}

void Orbitals::checkQueue()
{
  if (!m_runningMutex->tryLock())
    return;

  // Create a hash: keys=priority, values=indices

  QHash<int, int> hash;
  CalcState state;

  for (int i = 0; i < m_queue.size(); i++) {
    state = m_queue.at(i).state;

    // If there is already a running job, return.
    if (state == Running) {
      return;
    }

    if (state == NotStarted) {
      hash.insert(m_queue[i].priority, i);
    }
  }

  // Do nothing if all calcs are finished.
  if (hash.size() == 0) {
    m_runningMutex->unlock();
#ifndef NDEBUG
    qDebug() << "Finished queue.";
#endif
    return;
  }

  QList<int> priorities = hash.keys();
  qSort(priorities);
  startCalculation(hash.value(priorities.first()));
}

void Orbitals::startCalculation(unsigned int queueIndex)
{
  // This will launch calculateMesh when finished.
  m_currentRunningCalculation = queueIndex;

  calcInfo* info = &m_queue[m_currentRunningCalculation];

#ifndef NDEBUG
  qDebug() << info->orbital << " startCalculation() called";
#endif

  switch (info->state) {
    case NotStarted: // Start calculation
      calculateCube();
      break;
    case Running: // Nothing below should happen...
      qWarning() << "startCalculation called on a running calc...";
      break;
    case Completed:
      qWarning() << "startCalculation called on a completed calc...";
      break;
    case Canceled:
      qWarning() << "startCalculation called on a canceled calc...";
      break;
  }
}

void Orbitals::calculateCube()
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];

  info->state = Running;

  // Check if the cube we want already exists
  for (int i = 0; i < m_queue.size(); i++) {
    calcInfo* cI = &m_queue[i];
    if (cI->state == Completed && cI->orbital == info->orbital &&
        cI->resolution == info->resolution) {
      info->cube = cI->cube;
#ifndef NDEBUG
      qDebug() << "Reusing cube from calculation " << i << ":\n"
               << "\tOrbital " << cI->orbital << "\n"
               << "\tResolution " << cI->resolution;
#endif
      calculatePosMesh();
      return;
    }
  }

  // Create new cube
  Core::Cube* cube = m_molecule->addCube();
  info->cube = cube;
  cube->setLimits(*m_molecule, info->resolution, cubePadding);
  cube->setName("Molecular Orbital " + std::to_string(info->orbital + 1));
  cube->setCubeType(Core::Cube::Type::MO);

  if (!m_gaussianConcurrent) {
    m_gaussianConcurrent = new QtGui::GaussianSetConcurrent(this);
  }
  m_gaussianConcurrent->setMolecule(m_molecule);

  auto* watcher = &m_gaussianConcurrent->watcher();
  connect(watcher, SIGNAL(finished()), this, SLOT(calculateCubeDone()));

  m_dialog->initializeProgress(info->orbital, watcher->progressMinimum(),
                               watcher->progressMaximum(), 1, 3);

  connect(watcher, SIGNAL(progressValueChanged(int)), this,
          SLOT(updateProgress(int)));

#ifndef NDEBUG
  qDebug() << info->orbital << " Cube calculation started.";
#endif
  // TODO: add alpha / beta
  m_gaussianConcurrent->calculateMolecularOrbital(cube, info->orbital);
}

void Orbitals::calculateCubeDone()
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];

  auto* watcher = &m_gaussianConcurrent->watcher();
  watcher->disconnect(this);

  if (m_updateMesh) {
    calculatePosMesh();
  } else
    calculationComplete();
}

void Orbitals::calculatePosMesh()
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];

  info->state = Running;

  auto posMesh = m_molecule->addMesh();
  auto cube = info->cube;

  if (!m_meshGenerator) {
    m_meshGenerator = new QtGui::MeshGenerator;
  }
  connect(m_meshGenerator, SIGNAL(finished()), SLOT(calculatePosMeshDone()));
  m_meshGenerator->initialize(cube, posMesh, m_isoValue, smoothingPasses);
  m_meshGenerator->start();
}

void Orbitals::calculatePosMeshDone()
{
  disconnect(m_meshGenerator, 0, this, 0);
  calculateNegMesh();
}

void Orbitals::calculateNegMesh()
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];

  info->state = Running;

  auto negMesh = m_molecule->addMesh();
  auto cube = info->cube;

  if (!m_meshGenerator) {
    // shouldn't happen, but better to be careful
    m_meshGenerator = new QtGui::MeshGenerator;
  }
  connect(m_meshGenerator, SIGNAL(finished()), SLOT(calculateNegMeshDone()));
  // true indicates that we want to reverse the surface
  m_meshGenerator->initialize(cube, negMesh, -m_isoValue, smoothingPasses,
                              true);
  m_meshGenerator->start();
}

void Orbitals::calculateNegMeshDone()
{
  disconnect(m_meshGenerator, 0, this, 0);

  calculationComplete();

  // ask for a repaint
  m_molecule->emitChanged(QtGui::Molecule::Added);
}

void Orbitals::calculationComplete()
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];

  m_dialog->calculationComplete(info->orbital);

  info->state = Completed;
  m_currentRunningCalculation = -1;
  m_runningMutex->unlock();

#ifndef NDEBUG
  qDebug() << info->orbital << " all calculations complete.";
#endif
  checkQueue();
}

void Orbitals::renderOrbital(unsigned int row)
{
  if (row == 0)
    return;

  unsigned int orbital = row - 1;

#ifndef NDEBUG
  qDebug() << "Rendering orbital " << orbital;
#endif

  // Find the most recent calc matching the selected orbital:
  calcInfo calc;
  int index = -1;
  for (int i = 0; i < m_queue.size(); i++) {
    calc = m_queue[i];
    if (calc.orbital == orbital && calc.state == Completed) {
      index = i;
    }
  }

  // calculate the meshes
  m_molecule->clearMeshes();
  if (index == -1) {
    // need to calculate the cube first
    calculateOrbitalFromWidget(orbital, OrbitalWidget::OrbitalQualityToDouble(
                                          m_dialog->defaultQuality()));
  } else {
    // just need to update the meshes
    m_currentRunningCalculation = index;
    m_runningMutex->tryLock();
    calculatePosMesh(); // will eventually call negMesh too
  }

  // add the orbital to the renderer
  QStringList displayTypes;
  displayTypes << tr("Meshes");
  requestActiveDisplayTypes(displayTypes);
}

void Orbitals::updateProgress(int current)
{
  calcInfo* info = &m_queue[m_currentRunningCalculation];
  int orbital = info->orbital;
  m_dialog->updateProgress(orbital, current);
}

} // namespace Avogadro::QtPlugins
