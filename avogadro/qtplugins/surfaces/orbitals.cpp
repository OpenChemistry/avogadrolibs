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
#include <avogadro/core/mesh.h>
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

#include <utility>

namespace Avogadro::QtPlugins {

const double cubePadding = 5.0;
const int smoothingPasses = 1;

Orbitals::Orbitals(QObject* p)
  : ExtensionPlugin(p), m_action(new QAction(this)), m_molecule(nullptr),
    m_dialog(nullptr)
{
  m_action->setEnabled(false);
  m_action->setText(tr("Molecular Orbitals…"));
  connect(m_action, SIGNAL(triggered()), SLOT(openDialog()));
}

Orbitals::~Orbitals()
{
  // The workers write into m_pendingCube and the pending meshes, which are
  // members and go before the child calculator would stop them.
  stopCalculations();
  // Parentless QThread; ~MeshGenerator() waits for a running thread.
  delete m_meshGenerator;

  if (m_dialog)
    m_dialog->deleteLater();
  // molecule and basis are freed elsewhere
}

int Orbitals::cubeIndex(const std::weak_ptr<const Core::Cube>& cube) const
{
  const std::shared_ptr<const Core::Cube> locked = cube.lock();
  if (!locked || m_molecule == nullptr)
    return -1;
  for (Index j = 0; j < m_molecule->cubeCount(); ++j) {
    if (m_molecule->sharedCube(j) == locked)
      return static_cast<int>(j);
  }
  return -1;
}

bool Orbitals::hasLiveCube(calcInfo& info) const
{
  if (cubeIndex(info.cube) >= 0)
    return true;
  // Something else (the Surfaces dialog, say) cleared the molecule's cubes.
  info.cube.reset();
  if (info.state == Completed)
    info.state = Canceled;
  return false;
}

bool Orbitals::meshGeneratorBusy() const
{
  return m_meshGenerator != nullptr && m_meshGenerator->isRunning();
}

void Orbitals::stopCalculations()
{
  if (m_gaussianConcurrent) {
    auto& watcher = m_gaussianConcurrent->watcher();
    watcher.disconnect(this);
    watcher.cancel();
    watcher.waitForFinished();
  }
  if (m_meshGenerator) {
    disconnect(m_meshGenerator, nullptr, this, nullptr);
    // There is no way to interrupt a mesh generator, only to join it.
    m_meshGenerator->wait();
  }

  m_pendingCube.reset();
  m_meshCube.reset();
  m_pendingPosMesh.reset();
  m_pendingNegMesh.reset();
  m_meshPhase = MeshPhase::Idle;

  m_currentRunningCalculation = -1;
  m_currentMeshCalculation = -1;
  m_nextMeshCalculation = -1;
  m_runningCube = false;
}

QList<QAction*> Orbitals::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList Orbitals::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analyze");
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
  // sanity check if there are actually mo coefficients
  auto* basis = dynamic_cast<Core::GaussianSet*>(m_molecule->basisSet());
  if (basis == nullptr || basis->moMatrix().size() == 0)
    hasOrbitals = false;

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
  stopCalculations();
  m_queue.clear();

  loadBasis();

  if (!m_basis || m_basis->electronCount() == 0 || !hasOrbitals)
    return; // no electrons, no orbitals

  loadOrbitals();
  // Orbitals are calculated when one is selected, which is fast enough that
  // precalculating a window of them on every load is not worth the work --
  // renderOrbital() falls through to calculateOrbitalFromWidget() when there
  // is nothing cached. The dialog's "calculate all" still calls
  // precalculateOrbitals() when the user actually asks for it.
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

  auto* basis = dynamic_cast<Core::GaussianSet*>(m_molecule->basisSet());
  if (basis == nullptr || basis->moMatrix().size() == 0)
    return;

  if (!m_dialog) {
    m_dialog = new OrbitalWidget(qobject_cast<QWidget*>(parent()), Qt::Window);
    connect(m_dialog,
            SIGNAL(orbitalSelected(unsigned int, Core::BasisSet::ElectronType)),
            this,
            SLOT(renderOrbital(unsigned int, Core::BasisSet::ElectronType)));
    connect(m_dialog,
            SIGNAL(renderRequested(unsigned int, double,
                                   Core::BasisSet::ElectronType)),
            this,
            SLOT(calculateOrbitalFromWidget(unsigned int, double,
                                            Core::BasisSet::ElectronType)));
    connect(m_dialog, SIGNAL(calculateAll()), this,
            SLOT(precalculateOrbitals()));
  }

  m_dialog->fillTable(m_basis);
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void Orbitals::moleculeChanged([[maybe_unused]] unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  bool isEnabled = m_action->isEnabled();
  bool hasOrbitals = (m_molecule->basisSet() != nullptr);

  // sanity check if there are actually mo coefficients
  auto* basis = dynamic_cast<Core::GaussianSet*>(m_molecule->basisSet());
  if (basis == nullptr || basis->moMatrix().size() == 0)
    hasOrbitals = false;

  // Molecule::emitChanged() frees the basis set, cubes and meshes whenever
  // this holds. Queued calculations describe that structure and the table
  // rows describe the old basis, so both have to go - including when one
  // valid basis set replaces another and the enabled state never changes.
  const bool derivedDataDropped =
    QtGui::Molecule::invalidatesDerivedData(changes);
  if (derivedDataDropped) {
    stopCalculations();
    m_queue.clear();
    if (m_dialog)
      m_dialog->clearTable();
  }

  loadBasis(); // the cached pointer may have just been freed

  m_action->setEnabled(hasOrbitals);

  if (hasOrbitals) {
    if (!isEnabled) {
      loadOrbitals(); // orbitals appeared: fill the table and show the dialog
    } else if (derivedDataDropped && m_dialog && m_dialog->isVisible()) {
      // Refill in place; the dialog was already open, so do not raise it.
      m_dialog->fillTable(m_basis);
    }
  } else if (m_dialog) {
    m_dialog->hide();
  }
}

void Orbitals::openDialog()
{
  if (!m_dialog) {
    m_dialog = new OrbitalWidget(qobject_cast<QWidget*>(parent()), Qt::Window);
    connect(m_dialog,
            SIGNAL(orbitalSelected(unsigned int, Core::BasisSet::ElectronType)),
            this,
            SLOT(renderOrbital(unsigned int, Core::BasisSet::ElectronType)));
    connect(m_dialog,
            SIGNAL(renderRequested(unsigned int, double,
                                   Core::BasisSet::ElectronType)),
            this,
            SLOT(calculateOrbitalFromWidget(unsigned int, double,
                                            Core::BasisSet::ElectronType)));
    connect(m_dialog, SIGNAL(calculateAll()), this,
            SLOT(precalculateOrbitals()));
  }

  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void Orbitals::calculateOrbitalFromWidget(
  unsigned int orbital, double resolution,
  Core::BasisSet::ElectronType electronType)
{
  m_updateMesh = true;

  // check if the orbital is already in the queue (with same electron type)
  bool found = false;
  for (int i = 0; i < m_queue.size(); i++) {
    if (m_queue[i].orbital == orbital && m_queue[i].resolution == resolution &&
        m_queue[i].electronType == electronType) {
      // change the priority to the highest
      m_queue[i].priority = 0;
      // A cancelled calculation, or a result the molecule has since dropped,
      // has to be run (again).
      if (m_queue[i].state == Completed)
        hasLiveCube(m_queue[i]);
      if (m_queue[i].state == Canceled)
        m_queue[i].state = NotStarted;
      found = true;
      break;
    }
  }

  if (!found) {
    addCalculationToQueue(orbital, resolution, m_dialog->isovalue(),
                          electronType, 0);
  }
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
  unsigned int startIndex =
    (m_dialog->precalcLimit()) ? homo - (m_dialog->precalcRange() / 2) : 0;
  if (startIndex > homo) { // overflow check
    startIndex = 0;
  }
  unsigned int endIndex = (m_dialog->precalcLimit())
                            ? homo + (m_dialog->precalcRange() / 2) - 1
                            : m_basis->molecularOrbitalCount();
  if (endIndex >= m_basis->molecularOrbitalCount()) {
    endIndex = m_basis->molecularOrbitalCount() - 1;
  }

  // For now, precalculate paired/alpha orbitals only
  // TODO: For open-shell, could precalculate both alpha and beta
  for (unsigned int i = startIndex; i <= endIndex; i++) {
#ifndef NDEBUG
    qDebug() << " precalculate " << i << " priority " << priority;
#endif
    addCalculationToQueue(
      i, // orbital
      OrbitalWidget::OrbitalQualityToDouble(m_dialog->quality()),
      m_dialog->isovalue(), Core::BasisSet::Paired, priority);

    // Update priority. Stays the same when i = homo.
    if (i + 1 < homo)
      priority--;
    else if (i + 1 > homo)
      priority++;
  }
  checkQueue();
}

void Orbitals::addCalculationToQueue(unsigned int orbital, double resolution,
                                     double isovalue,
                                     Core::BasisSet::ElectronType electronType,
                                     unsigned int priority)
{
  // Create new queue entry
  calcInfo newCalc;
  newCalc.orbital = orbital;
  newCalc.electronType = electronType;
  newCalc.resolution = resolution;
  newCalc.isovalue = isovalue;
  newCalc.priority = priority;
  newCalc.state = NotStarted;

  // Add new calculation
  m_queue.append(newCalc);
}

void Orbitals::checkQueue()
{
  if (m_runningCube)
    return;
  m_runningCube = true;

  // Create a hash: keys=priority, values=indices

  QHash<int, int> hash;
  CalcState state;

  for (int i = 0; i < m_queue.size(); i++) {
    state = m_queue.at(i).state;

    // If there is already a running cube, return.
    if (state == Running) {
      return;
    }

    if (state == NotStarted) {
      hash.insert(m_queue[i].priority, i);
    }
  }

  // Do nothing if all calcs are finished.
  if (hash.size() == 0) {
    m_runningCube = false;
#ifndef NDEBUG
    qDebug() << "Finished queue.";
#endif
    return;
  }

  QList<int> priorities = hash.keys();
  std::sort(priorities.begin(), priorities.end());
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
  if (m_currentRunningCalculation == -1)
    return;

  calcInfo* info = &m_queue[m_currentRunningCalculation];

  info->state = Running;

  // Check if the cube we want already exists (must match electron type too)
  for (int i = 0; i < m_queue.size(); i++) {
    calcInfo* cI = &m_queue[i];
    if (cI->state == Completed && cI->orbital == info->orbital &&
        cI->resolution == info->resolution &&
        cI->electronType == info->electronType && hasLiveCube(*cI)) {
      info->cube = cI->cube;
#ifndef NDEBUG
      qDebug() << "Reusing cube from calculation " << i << ":\n"
               << "\tOrbital " << cI->orbital << "\n"
               << "\tResolution " << cI->resolution;
#endif
      // Set this cube as the active cube for volume rendering
      m_molecule->setActiveCubeIndex(static_cast<Index>(cubeIndex(cI->cube)));
      m_currentMeshCalculation = m_currentRunningCalculation;
      calculatePosMesh();
      calculationComplete();
      return;
    }
  }

  // Create new cube, filled off the molecule and published when done.
  m_pendingCube = std::make_unique<Core::Cube>();
  Core::Cube* cube = m_pendingCube.get();
  cube->setLimits(*m_molecule, info->resolution, cubePadding);
  cube->setName("Molecular Orbital " + std::to_string(info->orbital + 1));
  cube->setCubeType(Core::Cube::Type::MO);

  if (!m_gaussianConcurrent) {
    m_gaussianConcurrent = new QtGui::GaussianSetConcurrent(this);
  }
  m_gaussianConcurrent->setMolecule(m_molecule);

  auto* watcher = &m_gaussianConcurrent->watcher();
  connect(watcher, SIGNAL(finished()), this, SLOT(calculateCubeDone()));

#ifndef NDEBUG
  qDebug() << info->orbital << " Cube calculation started.";
#endif
  bool beta = (info->electronType == Core::BasisSet::Beta);
  if (!m_gaussianConcurrent->calculateMolecularOrbital(cube, info->orbital,
                                                       beta)) {
    // The basis set was refused; there is nothing to wait for.
    watcher->disconnect(this);
    m_pendingCube.reset();
    info->state = Canceled;
    m_currentRunningCalculation = -1;
    m_runningCube = false;
  }
}

void Orbitals::calculateCubeDone()
{
  auto* watcher = &m_gaussianConcurrent->watcher();
  watcher->disconnect(this);

  std::unique_ptr<Core::Cube> cube = std::move(m_pendingCube);
  if (m_currentRunningCalculation == -1 || !cube)
    return;

  if (watcher->isCanceled()) {
    // Stopped by someone else, e.g. the Surfaces dialog starting its own
    // calculation: the cube is only partly filled, so it is never shown.
    // Asking for the orbital again calculates it again.
    m_queue[m_currentRunningCalculation].state = Canceled;
    m_currentRunningCalculation = -1;
    m_runningCube = false;
    checkQueue();
    return;
  }

  const Index index = m_molecule->cubeCount();
  m_molecule->addCube(std::move(cube));
  // Set this cube as the active cube for volume rendering
  m_molecule->setActiveCubeIndex(index);
  m_queue[m_currentRunningCalculation].cube = m_molecule->sharedCube(index);

  if (m_updateMesh) {
    if (m_currentMeshCalculation == -1 || !meshGeneratorBusy()) {
      m_nextMeshCalculation = -1;
      m_currentMeshCalculation = m_currentRunningCalculation;
      calculatePosMesh();
    } else {
      m_nextMeshCalculation = m_currentRunningCalculation;
    }
  }
  calculationComplete();
}

void Orbitals::calculatePosMesh()
{
  if (m_currentMeshCalculation == -1)
    return;

  calcInfo* info = &m_queue[m_currentMeshCalculation];

  // A job this one supersedes may still be writing into the pending meshes.
  if (m_meshGenerator) {
    disconnect(m_meshGenerator, nullptr, this, nullptr);
    m_meshGenerator->wait();
  }
  m_pendingPosMesh.reset();
  m_pendingNegMesh.reset();
  m_meshPhase = MeshPhase::Idle;

  if (!hasLiveCube(*info)) {
    // The molecule dropped the cube; there is nothing left to mesh.
    m_meshCube.reset();
    m_currentMeshCalculation = -1;
    meshComplete();
    return;
  }
  // The handle keeps the cube alive for the generator, whatever happens to
  // the molecule's own list meanwhile.
  m_meshCube =
    m_molecule->sharedCube(static_cast<Index>(cubeIndex(info->cube)));
  m_pendingPosMesh = std::make_unique<Core::Mesh>();

  if (!m_meshGenerator) {
    m_meshGenerator = new QtGui::MeshGenerator;
  }
  connect(m_meshGenerator, SIGNAL(finished()), SLOT(calculatePosMeshDone()));
  m_meshGenerator->initialize(m_meshCube.get(), m_pendingPosMesh.get(),
                              info->isovalue, smoothingPasses);
  m_meshPhase = MeshPhase::Positive;
  m_meshGenerator->start();
}

void Orbitals::calculatePosMeshDone()
{
  // Ignore a finished() left over from a job that was superseded.
  if (m_meshPhase != MeshPhase::Positive || meshGeneratorBusy())
    return;
  disconnect(m_meshGenerator, nullptr, this, nullptr);
  calculateNegMesh();
}

void Orbitals::calculateNegMesh()
{
  if (m_currentMeshCalculation == -1 || !m_meshCube)
    return;

  calcInfo* info = &m_queue[m_currentMeshCalculation];

  m_pendingNegMesh = std::make_unique<Core::Mesh>();

  if (!m_meshGenerator) {
    // shouldn't happen, but better to be careful
    m_meshGenerator = new QtGui::MeshGenerator;
  }
  connect(m_meshGenerator, SIGNAL(finished()), SLOT(calculateNegMeshDone()));
  // true indicates that we want to reverse the surface
  m_meshGenerator->initialize(m_meshCube.get(), m_pendingNegMesh.get(),
                              -info->isovalue, smoothingPasses, true);
  m_meshPhase = MeshPhase::Negative;
  m_meshGenerator->start();
}

void Orbitals::calculateNegMeshDone()
{
  // Ignore a finished() left over from a job that was superseded.
  if (m_meshPhase != MeshPhase::Negative || meshGeneratorBusy())
    return;
  disconnect(m_meshGenerator, nullptr, this, nullptr);
  m_meshPhase = MeshPhase::Idle;

  // Replace the previous orbital's pair with both new meshes at once, so the
  // renderer never shows half of an orbital.
  std::unique_ptr<Core::Mesh> posMesh = std::move(m_pendingPosMesh);
  std::unique_ptr<Core::Mesh> negMesh = std::move(m_pendingNegMesh);
  m_meshCube.reset();
  m_molecule->clearMeshes();
  m_molecule->addMesh(std::move(posMesh));
  m_molecule->addMesh(std::move(negMesh));

  meshComplete();
  // make sure the display type is turned on
  QStringList displayTypes;
  displayTypes << tr("Surfaces");
  emit requestActiveDisplayTypes(displayTypes);

  // ask for a repaint
  m_molecule->emitChanged(QtGui::Molecule::Added);
}

void Orbitals::meshComplete()
{
  if (m_nextMeshCalculation != -1) {
    // start the next mesh calculation
    m_currentMeshCalculation = m_nextMeshCalculation;
    m_nextMeshCalculation = -1;
    calculatePosMesh();
    return;
  } else
    m_currentMeshCalculation = -1;
}

void Orbitals::calculationComplete()
{
  if (m_currentRunningCalculation == -1)
    return;

  calcInfo* info = &m_queue[m_currentRunningCalculation];

  info->state = Completed;
  m_currentRunningCalculation = -1;
  m_runningCube = false;

#ifndef NDEBUG
  qDebug() << info->orbital << " all calculations complete.";
#endif
  checkQueue();
}

void Orbitals::renderOrbital(unsigned int orbital,
                             Core::BasisSet::ElectronType electronType)
{
#ifndef NDEBUG
  qDebug() << "Rendering orbital " << orbital
           << " electronType: " << static_cast<int>(electronType);
#endif

  double targetResolution =
    OrbitalWidget::OrbitalQualityToDouble(m_dialog->quality());

  // Reuse a completed cube at the requested resolution or finer
  int index = -1;
  for (int i = 0; i < m_queue.size(); i++) {
    const calcInfo& calc = m_queue[i];
    if (calc.orbital == orbital && calc.electronType == electronType &&
        calc.state == Completed && calc.resolution <= targetResolution + 1e-6 &&
        (index == -1 || calc.resolution < m_queue[index].resolution) &&
        hasLiveCube(m_queue[i])) {
      index = i;
    }
  }

  // calculate the meshes
  if (index == -1) {
    // need to calculate the cube first with the selected quality resolution
    calculateOrbitalFromWidget(orbital, targetResolution, electronType);
  } else {
    // Set this cube as the active cube for volume rendering
    m_molecule->setActiveCubeIndex(
      static_cast<Index>(cubeIndex(m_queue[index].cube)));

    // just need to update the meshes, using the current isovalue
    m_queue[index].isovalue = m_dialog->isovalue();
    // A job whose generator has stopped may have lost its finished() to
    // MeshGenerator::cancelAllCalculations(); start this one in its place.
    // A job queued behind the lost one is dropped too.
    if (m_currentMeshCalculation == -1 || !meshGeneratorBusy()) {
      m_nextMeshCalculation = -1;
      m_currentMeshCalculation = index;
      calculatePosMesh(); // will eventually call negMesh too
    } else {
      // queue it up
      m_nextMeshCalculation = index;
    }
  }

  // add the orbital to the renderer
  QStringList displayTypes;
  displayTypes << tr("Surfaces");
  emit requestActiveDisplayTypes(displayTypes);
}

} // namespace Avogadro::QtPlugins
