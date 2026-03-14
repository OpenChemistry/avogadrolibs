/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "autoopt.h"
#include "csvrthermostat.h"

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/lennardjones.h>

#include <avogadro/core/contrastcolor.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/calcworker.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QAction>
#include <QFormLayout>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QPushButton>
#include <QSettings>
#include <QElapsedTimer>
#include <QThread>
#include <QTimer>

#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <QDebug>

using Avogadro::QtGui::Molecule;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::Identifier;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;

namespace Avogadro::QtPlugins {

using QtGui::Molecule;
using QtGui::RWAtom;

#define ROTATION_SPEED 0.5

AutoOpt::AutoOpt(QObject* parent_)
  : QtGui::ToolPlugin(parent_), m_activateAction(new QAction(this)),
    m_molecule(nullptr), m_renderer(nullptr), m_pressedButtons(Qt::NoButton),
    m_toolWidget(nullptr), m_currentMethod("LJ")
{
  QString shortcut = tr("Ctrl+7", "control-key 7");
  m_activateAction->setText(tr("Auto Optimize"));
  m_activateAction->setToolTip(
    tr("Auto Optimize Tool\t(%1)\n\n"
       "Navigation Functions when clicking in empty space.\n"
       "Left Mouse:\tRotate Space\n"
       "Middle Mouse:\tZoom Space\n"
       "Right Mouse:\tMove Space\n"
       "Double-Click:\tReset View\n\n"
       "When running:\n"
       "Left Mouse:\tClick and drag atoms to move them.\n"
       "Right Mouse:\tClick and drag to rotate atoms.")
      .arg(shortcut));
  setIcon();

  // used to run the optimization step
  connect(&m_timer, &QTimer::timeout, this, &AutoOpt::optimizeStep);

  // set up the the thermostat
  m_thermostat =
    new CSVRThermostat(m_temperature, m_timeStep, m_timeStep * 200.0);
}

AutoOpt::~AutoOpt()
{
  cleanupWorker();
  delete m_thermostat;
}

void AutoOpt::cleanupWorker()
{
  if (m_workerThread) {
    m_workerThread->quit();
    m_workerThread->wait(5000);
    m_workerThread = nullptr;
    m_worker = nullptr;
  }
  m_computePending = false;
}

void AutoOpt::startWorker()
{
  cleanupWorker();

  auto n = m_molecule->atomCount();
  auto mask = m_molecule->molecule().frozenAtomMask();
  if (mask.rows() != static_cast<Eigen::Index>(3 * n))
    mask = Eigen::VectorXd::Ones(3 * n);

  auto constraints = m_molecule->molecule().constraints();

  auto* calc = Calc::EnergyManager::instance().model(m_currentMethod);
  if (calc == nullptr)
    return;

  Core::Molecule snapshot =
    static_cast<const Core::Molecule&>(m_molecule->molecule());

  m_workerThread = new QThread(this);
  m_worker = new QtGui::CalcWorker();
  m_worker->moveToThread(m_workerThread);

  connect(m_workerThread, &QThread::finished, m_worker, &QObject::deleteLater);
  m_workerThread->start();

  // Connect signals based on task
  if (m_task == 0) {
    connect(m_worker, &QtGui::CalcWorker::optimizeFinished, this,
            &AutoOpt::onOptimizeStepDone);
  } else {
    connect(m_worker, &QtGui::CalcWorker::evaluateFinished, this,
            &AutoOpt::onGradientDone);
  }
  connect(m_worker, &QtGui::CalcWorker::calculatorReady, this,
          &AutoOpt::onWorkerReady);

  // Now invoke initCalculator after connections are established
  QMetaObject::invokeMethod(
    m_worker, "initCalculator", Qt::QueuedConnection,
    Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
    Q_ARG(Avogadro::Core::Molecule, snapshot), Q_ARG(Eigen::VectorXd, mask),
    Q_ARG(std::vector<Avogadro::Core::Constraint>, constraints));
}

void AutoOpt::setIcon(bool darkTheme)
{
  Q_UNUSED(darkTheme);
  m_activateAction->setIcon(QIcon(":/icons/autoopt.svg"));
}

void setMasses(Eigen::ArrayXd& masses, const QtGui::Molecule* mol)
{
  masses.resize(mol->atomCount() * 3); // 3N to match coordinates
  for (unsigned int i = 0; i < mol->atomCount(); i++) {
    Real mass = mol->atom(i).mass();
    if (mass < 0.5)
      mass = 1.0; // for dummy atoms

    masses[i * 3] = mass;
    masses[i * 3 + 1] = mass;
    masses[i * 3 + 2] = mass;
  }
}

void AutoOpt::setMolecule(QtGui::Molecule* mol)
{
  if (mol != nullptr) {
    m_molecule = mol->undoMolecule();
    // connect to any molecule changes
    connect(mol, SIGNAL(changed(unsigned int)),
            SLOT(moleculeChanged(unsigned int)));

    setMasses(m_masses, mol);
  }
}

void AutoOpt::moleculeChanged(unsigned int changes)
{
  // qDebug() << "molecule changed" << changes;
  if (m_running && (changes != (Molecule::Atoms | Molecule::Moved))) {
    // restart
    stop();
    start();
  }
}

QWidget* AutoOpt::toolWidget() const
{
  QSettings settings;
  if (!m_toolWidget && m_molecule) {
    m_toolWidget = new QWidget();
    m_toolWidget->setWindowTitle("AutoOptimization");

    // set up a form layout
    QFormLayout* form = new QFormLayout(m_toolWidget);

    QComboBox* taskComboBox = new QComboBox();
    taskComboBox->setObjectName("taskComboBox");
    taskComboBox->addItem(tr("Optimize"));
    taskComboBox->addItem(tr("Dynamics"));
    taskComboBox->setCurrentIndex(0);
    connect(taskComboBox, &QComboBox::currentIndexChanged, this,
            &AutoOpt::taskChanged);
    form->addRow(tr("Task:"), taskComboBox);

    // method combo box
    QComboBox* methodComboBox = new QComboBox();
    methodComboBox->setObjectName("methodComboBox");
    // check the methods for this molecule
    auto mol = m_molecule->molecule();
    auto list = Calc::EnergyManager::instance().identifiersForMolecule(mol);
    for (auto option : list) {
      methodComboBox->addItem(option.c_str());
    }

    // check for the previous saved method
    auto recommended = Calc::EnergyManager::instance().recommendedModel(mol);
    QString currentMethod =
      settings.value("autoopt/method", recommended.c_str()).toString();

    // check to make sure currentMethod is in the list
    // otherwise use recommended
    if (!methodComboBox->findText(currentMethod))
      currentMethod = recommended.c_str();
    methodComboBox->setCurrentIndex(methodComboBox->findText(currentMethod));

    connect(methodComboBox, &QComboBox::currentTextChanged, this,
            &AutoOpt::methodChanged);
    form->addRow(tr("Method:"), methodComboBox);

    // add a temperature double spin box for dynamics
    QDoubleSpinBox* temperatureSpinBox = new QDoubleSpinBox();
    temperatureSpinBox->setObjectName("temperatureSpinBox");
    temperatureSpinBox->setRange(0.0, 1000.0);
    temperatureSpinBox->setSingleStep(1.0);
    temperatureSpinBox->setDecimals(1);
    temperatureSpinBox->setSuffix(" K"); // don't translate units
    temperatureSpinBox->setValue(300.0);
    connect(temperatureSpinBox, &QDoubleSpinBox::valueChanged, this,
            &AutoOpt::temperatureChanged);
    form->addRow(tr("Temperature:"), temperatureSpinBox);

    // add a timestep double spin box for dynamics
    QDoubleSpinBox* timeStepSpinBox = new QDoubleSpinBox();
    timeStepSpinBox->setObjectName("timeStepSpinBox");
    timeStepSpinBox->setRange(0.1, 10.0);
    timeStepSpinBox->setSingleStep(0.5);
    timeStepSpinBox->setDecimals(1);
    timeStepSpinBox->setSuffix(" fs"); // don't translate units
    timeStepSpinBox->setValue(1.0);
    connect(timeStepSpinBox, &QDoubleSpinBox::valueChanged, this,
            &AutoOpt::timeStepChanged);
    form->addRow(tr("Timestep:"), timeStepSpinBox);

    // disable the temperature and timestep for now
    temperatureSpinBox->setEnabled(false);
    timeStepSpinBox->setEnabled(false);

    // start stop button
    QPushButton* startStopButton = new QPushButton(tr("Start"));
    startStopButton->setObjectName("startStopButton");
    startStopButton->setIcon(QIcon::fromTheme("go-down"));
    connect(startStopButton, &QPushButton::clicked, this, &AutoOpt::startStop);
    form->addRow(startStopButton);

    m_toolWidget->setLayout(form);
  }
  return m_toolWidget;
}

void AutoOpt::taskChanged(int index)
{
  m_task = index;

  auto temperatureSpinBox =
    m_toolWidget->findChild<QDoubleSpinBox*>("temperatureSpinBox");
  auto timeStepSpinBox =
    m_toolWidget->findChild<QDoubleSpinBox*>("timeStepSpinBox");

  bool enabled = (index == 1);
  temperatureSpinBox->setEnabled(enabled);
  timeStepSpinBox->setEnabled(enabled);

  if (index == 1) { // dynamics
    // enable the temperature and timestep
    disconnect(&m_timer, &QTimer::timeout, this, &AutoOpt::optimizeStep);
    connect(&m_timer, &QTimer::timeout, this, &AutoOpt::dynamicsStep);
  } else {
    // disable the temperature and timestep
    disconnect(&m_timer, &QTimer::timeout, this, &AutoOpt::dynamicsStep);
    connect(&m_timer, &QTimer::timeout, this, &AutoOpt::optimizeStep);
  }
}

void AutoOpt::temperatureChanged(double temp)
{
  m_temperature = temp;
}

void AutoOpt::timeStepChanged(double timeStep)
{
  m_timeStep = timeStep;
}

void AutoOpt::startStop()
{
  if (m_running)
    stop();
  else
    start();
}

void AutoOpt::start()
{
  // get the button from the widget
  QPushButton* startStopButton =
    m_toolWidget->findChild<QPushButton*>("startStopButton");
  startStopButton->setText(tr("Stop"));
  startStopButton->setIcon(QIcon::fromTheme("process-stop"));
  m_running = true;

  // make sure method is set
  if (m_toolWidget) {
    auto comboBox = m_toolWidget->findChild<QComboBox*>("methodComboBox");
    QString currentMethod = comboBox->currentText();
    m_currentMethod = currentMethod.toStdString();
  }

  m_molecule->beginMergeMode("AutoOpt");

  m_energy = 0.0;
  m_deltaE = 0.0;

  // set up masses first (needed for velocity initialization)
  setMasses(m_masses, &m_molecule->molecule());

  // set the initial velocities
  m_velocities.resize(m_molecule->atomCount() * 3);
  m_acceleration.resize(m_molecule->atomCount() * 3);
  m_acceleration.setZero();
  m_firstStep = true; // reset for Velocity Verlet
  if (m_task == 1) {
    // For dynamics, initialize to Maxwell-Boltzmann distribution
    m_thermostat->setTargetTemperature(m_temperature);

    // Count free coordinates from the frozen atom mask
    auto mask = m_molecule->molecule().frozenAtomMask();
    int freeDOF = 3 * m_molecule->atomCount();
    if (mask.rows() == freeDOF)
      freeDOF = static_cast<int>(mask.sum());
    // Subtract 3 for overall translation unless periodic (unit cell)
    if (m_molecule->molecule().unitCell() == nullptr)
      freeDOF -= 3;
    m_thermostat->setDegreesOfFreedom(std::max(freeDOF, 1));

    m_thermostat->initializeVelocities(m_velocities, m_masses);
  } else {
    m_velocities.setZero();
  }

  // Start the worker thread — timer begins in onWorkerReady
  startWorker();

  emit drawablesChanged();
}

void AutoOpt::onWorkerReady()
{
  if (!m_running)
    return;

  // Now that the worker is ready, start the timer
  qint64 minimumStep = 33; // 30 fps
  m_oneStepTime = minimumStep;
  m_timer.start(m_oneStepTime);
}

void AutoOpt::stop()
{
  m_timer.stop();
  m_running = false;

  cleanupWorker();

  // get the button from the widget
  QPushButton* startStopButton =
    m_toolWidget->findChild<QPushButton*>("startStopButton");
  startStopButton->setText(tr("Start"));
  startStopButton->setIcon(QIcon::fromTheme("go-down"));

  m_molecule->endMergeMode();

  emit drawablesChanged();
}

void AutoOpt::methodChanged(const QString& method)
{
  m_currentMethod = method.toStdString();
  // save the choice for next time
  QSettings settings;
  settings.setValue("autoopt/method", method);

  // need to stop the current optimization,
  // then restart after a brief pause
  if (m_running) {
    stop();
    start();
  }
}

void AutoOpt::optimizeStep()
{
  if (!m_running) {
    m_timer.stop();
    return;
  }

  // Skip if a previous computation is still in progress
  if (m_computePending || !m_worker)
    return;

  int n = m_molecule->atomCount();
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  Calc::OptimizationOptions options;
  options.algorithm = Calc::OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 2;

  m_computePending = true;
  QMetaObject::invokeMethod(
    m_worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, positions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, options));
}

void AutoOpt::onOptimizeStepDone(Eigen::VectorXd positions,
                                 Eigen::VectorXd gradient, double energy,
                                 bool converged)
{
  Q_UNUSED(gradient);
  Q_UNUSED(converged);
  m_computePending = false;

  if (!m_running || m_molecule == nullptr)
    return;

  int n = m_molecule->atomCount();

  if (std::isfinite(energy) && positions.allFinite()) {
    m_deltaE = energy - m_energy;
    m_energy = energy;

    Core::Array<Vector3> pos(n);
    Eigen::Map<Eigen::VectorXd>(pos[0].data(), 3 * n) = positions;

    m_molecule->setAtomPositions3d(pos, tr("Optimize Geometry"));
    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Moved;
    m_molecule->emitChanged(changes);
  }
}

void AutoOpt::dynamicsStep()
{
  if (!m_running) {
    m_timer.stop();
    return;
  }

  // Skip if a previous computation is still in progress
  if (m_computePending || !m_worker)
    return;

  int n = m_molecule->atomCount();
  double dt = m_timeStep;

  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  Eigen::Map<Eigen::VectorXd> map(pos[0].data(), 3 * n);
  Eigen::VectorXd positions = map;

  // get the frozen atoms
  auto mask = m_molecule->molecule().frozenAtomMask();
  if (mask.rows() != 3 * n)
    mask = Eigen::VectorXd::Ones(3 * n);

  // check m_masses
  if (m_masses.rows() != 3 * n)
    setMasses(m_masses, &(m_molecule->molecule()));

  // Velocity Verlet Step 1: Update positions
  // x(t+dt) = x(t) + v(t)*dt + 0.5*a(t)*dt^2
  Eigen::VectorXd velocityTerm = m_velocities * dt;
  Eigen::VectorXd accelTerm = 0.5 * m_acceleration * dt * dt;

  // zero out frozen atoms from the mask
  velocityTerm = velocityTerm.array() * mask.array();
  accelTerm = accelTerm.array() * mask.array();

  Eigen::VectorXd newPositions = positions + velocityTerm + accelTerm;

  // Limit maximum displacement per atom to prevent instability.
  const double baseDisplacement = 0.33 * std::sqrt(12.0 / 300.0);
  Eigen::ArrayXd maxDisplacements =
    baseDisplacement * (m_temperature / m_masses).sqrt();
  Eigen::VectorXd displacement = newPositions - positions;
  for (int i = 0; i < n; ++i) {
    double dist = displacement.segment<3>(3 * i).norm();
    double limit = maxDisplacements[3 * i];
    if (dist > limit) {
      double scale = limit / dist;
      displacement.segment<3>(3 * i) *= scale;
      m_velocities.segment<3>(3 * i) *= scale;
    }
  }
  newPositions = positions + displacement;

  // Update molecule positions immediately (visual feedback)
  if (newPositions.allFinite()) {
    Core::Array<Vector3> newPos(n);
    Eigen::Map<Eigen::VectorXd>(newPos[0].data(), 3 * n) = newPositions;
    m_molecule->setAtomPositions3d(newPos, tr("Molecular Dynamics"));
    Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Moved;
    m_molecule->emitChanged(changes);
  }

  // Send newPositions to worker for gradient computation (Verlet Step 2)
  m_computePending = true;
  QMetaObject::invokeMethod(m_worker, "runGradient", Qt::QueuedConnection,
                            Q_ARG(Eigen::VectorXd, newPositions));
}

void AutoOpt::onGradientDone(Eigen::VectorXd gradient, double energy)
{
  Q_UNUSED(energy);
  m_computePending = false;

  if (!m_running || m_molecule == nullptr)
    return;

  int n = m_molecule->atomCount();
  double dt = m_timeStep;

  auto mask = m_molecule->molecule().frozenAtomMask();
  if (mask.rows() != 3 * n)
    mask = Eigen::VectorXd::Ones(3 * n);

  // update the thermostat settings
  int freeDOF = static_cast<int>(mask.sum());
  if (m_molecule->molecule().unitCell() == nullptr)
    freeDOF -= 3;
  m_thermostat->setTargetTemperature(m_temperature);
  m_thermostat->setTimeStep(m_timeStep);
  m_thermostat->setDegreesOfFreedom(std::max(freeDOF, 1));

  // Guard against NaN/Inf from the gradient
  if (!gradient.allFinite())
    gradient.setZero();

  Eigen::VectorXd newAcceleration =
    -units::FORCE_CONVERSION * gradient.array() / m_masses.array();

  if (m_firstStep) {
    m_acceleration = newAcceleration;
    m_firstStep = false;
  }

  // Velocity Verlet Step 3: Update velocities
  // v(t+dt) = v(t) + 0.5*(a(t) + a(t+dt))*dt
  m_velocities += 0.5 * (m_acceleration + newAcceleration) * dt;

  // zero out frozen coords from the mask
  m_velocities = m_velocities.array() * mask.array();
  newAcceleration = newAcceleration.array() * mask.array();

  // Store new acceleration for next step
  m_acceleration = newAcceleration;

  // Apply thermostat
  m_thermostat->apply(m_velocities, m_masses);

#ifndef NDEBUG
  qDebug() << " temperature "
           << m_thermostat->compute_temperature(m_velocities, m_masses);
#endif
}

void AutoOpt::draw(Rendering::GroupNode& node)
{
  if (!m_running)
    return; // nothing to draw

  QString overlayText;
  if (m_task == 1) {
    // dynamics step
    double temp = m_thermostat->compute_temperature(m_velocities, m_masses);
    overlayText = tr("%1 T = %L2", "temperature in Kelvin")
                    .arg(m_currentMethod.c_str())
                    .arg(temp, 0, 'f', 1) +
                  " K";
  } else {
    overlayText = tr("%1 ΔE = %L2", "change in energy in kJ/mol")
                    .arg(m_currentMethod.c_str())
                    .arg(m_deltaE, 0, 'f', 2) +
                  " kJ/mol";
  }

  auto* geo = new GeometryNode;
  node.addChild(geo);

  TextProperties overlayTProp;
  overlayTProp.setFontFamily(TextProperties::Mono);

  // black text as a default
  Vector3ub color(0, 0, 0);
  if (m_renderer) {
    auto backgroundColor = m_renderer->scene().backgroundColor();
    color = Core::contrastColor(
      Vector3ub(backgroundColor[0], backgroundColor[1], backgroundColor[2]));
  }

  overlayTProp.setColorRgb(color[0], color[1], color[2]);
  overlayTProp.setAlign(TextProperties::HLeft, TextProperties::VTop);

  auto* label = new TextLabel2D;
  label->setText(overlayText.toStdString());
  label->setTextProperties(overlayTProp);
  label->setRenderPass(Rendering::Overlay2DPass);
  // align to the top left so get the viewport height
  int height = m_renderer->camera().height();
  label->setAnchor(Vector2i(10, height - 10));

  geo->addDrawable(label);
}

QUndoCommand* AutoOpt::keyPressEvent(QKeyEvent* e)
{
  switch (e->key()) {
    case Qt::Key_Left:
    case Qt::Key_H:
    case Qt::Key_A:
      translate(Vector3(-0.1, 0.0, 0.0));
      e->accept();
      break;
    case Qt::Key_Right:
    case Qt::Key_L:
    case Qt::Key_D:
      translate(Vector3(+0.1, 0.0, 0.0));
      e->accept();
      break;
    case Qt::Key_Up:
    case Qt::Key_K:
    case Qt::Key_W:
      translate(Vector3(0.0, +0.1, 0.0));
      e->accept();
      break;
    case Qt::Key_Down:
    case Qt::Key_J:
    case Qt::Key_S:
      translate(Vector3(0.0, -0.1, 0.0));
      e->accept();
      break;
    default:
      e->ignore();
  }
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  return nullptr;
}

QUndoCommand* AutoOpt::mousePressEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return nullptr;

  updatePressedButtons(e, false);
  m_lastMousePosition = e->pos();
  Vector2f windowPos(e->localPos().x(), e->localPos().y());
  m_lastMouse3D = m_renderer->camera().unProject(windowPos);

  if (m_molecule) {
    m_molecule->setInteractive(true);
  }

  if (m_pressedButtons & Qt::LeftButton) {
    m_object = m_renderer->hit(e->pos().x(), e->pos().y());

    switch (m_object.type) {
      case Rendering::AtomType:
        e->accept();
        return nullptr;
      default:
        break;
    }
  }

  return nullptr;
}

QUndoCommand* AutoOpt::mouseReleaseEvent(QMouseEvent* e)
{
  if (!m_renderer)
    return nullptr;

  updatePressedButtons(e, true);

  if (m_object.type == Rendering::InvalidType)
    return nullptr;

  if (m_molecule) {
    m_molecule->setInteractive(false);
  }

  switch (e->button()) {
    case Qt::LeftButton:
    case Qt::RightButton:
      resetObject();
      e->accept();
      break;
    default:
      break;
  }

  return nullptr;
}

QUndoCommand* AutoOpt::mouseMoveEvent(QMouseEvent* e)
{
  // if we're dragging through empty space, just return and ignore
  // (e.g., fall back to the navigate tool)
  const Core::Molecule* mol = &m_molecule->molecule();
  if (mol->isSelectionEmpty() && m_object.type == Rendering::InvalidType) {
    e->ignore();
    return nullptr;
  }

  updatePressedButtons(e, false);
  e->ignore();

  Vector2f windowPos(e->localPos().x(), e->localPos().y());

  if (mol->isSelectionEmpty() && m_object.type == Rendering::AtomType &&
      m_object.molecule == &m_molecule->molecule()) {
    // translate single atom position
    RWAtom atom = m_molecule->atom(m_object.index);
    Vector3f oldPos(atom.position3d().cast<float>());
    Vector3f newPos = m_renderer->camera().unProject(windowPos, oldPos);
    atom.setPosition3d(newPos.cast<double>());
  } else if (!mol->isSelectionEmpty()) {
    // update all selected atoms
    Vector3f newPos = m_renderer->camera().unProject(windowPos);
    Vector3 delta = (newPos - m_lastMouse3D).cast<double>();

    if (m_currentAction == Translation) {
      translate(delta);
    } else {
      // get the center of the selected atoms
      Vector3 centroid(0.0, 0.0, 0.0);
      unsigned long selectedAtomCount = 0;
      for (Index i = 0; i < m_molecule->atomCount(); ++i) {
        if (!m_molecule->atomSelected(i))
          continue;

        centroid += m_molecule->atomPosition3d(i);
        selectedAtomCount++;
      }
      if (selectedAtomCount > 0)
        centroid /= selectedAtomCount;

      if (m_currentAction == Rotation) {
        rotate(delta, centroid);
      } else if (m_currentAction == ZoomTilt) {
        tilt(delta, centroid);
      }
    }

    // now that we've moved things, save the position
    m_lastMouse3D = newPos;
  }

  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  e->accept();
  return nullptr;
}

void AutoOpt::translate(Vector3 delta, bool moveSelected)
{
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (moveSelected && !m_molecule->atomSelected(i))
      continue;
    else if (!moveSelected && m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(i, currentPos + delta.cast<double>());
  }
}

void AutoOpt::rotate(Vector3 delta, Vector3 centroid, bool moveSelected)
{
  // Rotate the selected atoms about the center
  // rotate only selected primitives
  Rendering::Camera* camera = &m_renderer->camera();
  Eigen::Vector3d backTransformX =
    camera->modelView().cast<double>().linear().row(0).transpose().normalized();
  Eigen::Vector3d backTransformY =
    camera->modelView().cast<double>().linear().row(1).transpose().normalized();

  Eigen::Projective3d fragmentRotation;
  fragmentRotation.matrix().setIdentity();
  fragmentRotation.translation() = centroid;
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[1] * ROTATION_SPEED, backTransformX));
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[0] * ROTATION_SPEED, backTransformY));
  fragmentRotation.translate(-centroid);

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (moveSelected && !m_molecule->atomSelected(i))
      continue;
    else if (!moveSelected && m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(
      i, (fragmentRotation * currentPos.homogeneous()).head<3>());
  }
}

void AutoOpt::axisRotate(Vector3 delta, Vector3 centroid, bool moveSelected)
{
  // rotate by the x, y, z axes by delta[0], delta[1], delta[2]
  // (in radians)
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (moveSelected && !m_molecule->atomSelected(i))
      continue;
    else if (!moveSelected && m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    Eigen::Projective3d fragmentRotation;
    fragmentRotation.matrix().setIdentity();
    fragmentRotation.translation() = centroid;

    // Rotate around the x-axis
    fragmentRotation.rotate(
      Eigen::AngleAxisd(delta[0], Vector3(1.0, 0.0, 0.0)));
    // Rotate around the y-axis
    fragmentRotation.rotate(
      Eigen::AngleAxisd(delta[1], Vector3(0.0, 1.0, 0.0)));
    // Rotate around the z-axis
    fragmentRotation.rotate(
      Eigen::AngleAxisd(delta[2], Vector3(0.0, 0.0, 1.0)));

    fragmentRotation.translate(-centroid);
    m_molecule->setAtomPosition3d(
      i, (fragmentRotation * currentPos.homogeneous()).head<3>());
  }
}

void AutoOpt::tilt(Vector3 delta, Vector3 centroid)
{
  // Rotate the selected atoms about the center
  // rotate only selected primitives
  Rendering::Camera* camera = &m_renderer->camera();
  Eigen::Vector3d backTransformZ =
    camera->modelView().cast<double>().linear().row(2).transpose().normalized();

  Eigen::Projective3d fragmentRotation;
  fragmentRotation.matrix().setIdentity();
  fragmentRotation.translation() = centroid;
  fragmentRotation.rotate(
    Eigen::AngleAxisd(delta[0] * ROTATION_SPEED, backTransformZ));
  fragmentRotation.translate(-centroid);

  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i))
      continue;

    Vector3 currentPos = m_molecule->atomPosition3d(i);
    m_molecule->setAtomPosition3d(
      i, (fragmentRotation * currentPos.homogeneous()).head<3>());
  }
}

void AutoOpt::updatePressedButtons(QMouseEvent* e, bool release)
{
  if (release)
    m_pressedButtons &= e->buttons();
  else
    m_pressedButtons |= e->buttons();

  // check for modifier keys (e.g., Mac)
  if (e->buttons() & Qt::LeftButton && e->modifiers() == Qt::NoModifier) {
    m_currentAction = Translation;
  } else if (e->buttons() & Qt::MiddleButton ||
             (e->buttons() & Qt::LeftButton &&
              e->modifiers() == Qt::ShiftModifier)) {
    m_currentAction = ZoomTilt;
  } else if (e->buttons() & Qt::RightButton ||
             (e->buttons() & Qt::LeftButton &&
              (e->modifiers() == Qt::ControlModifier ||
               e->modifiers() == Qt::MetaModifier))) {
    m_currentAction = Rotation;
  }
}

} // namespace Avogadro::QtPlugins
