/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "autoopt.h"

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/lennardjones.h>

#include <cppoptlib/meta.h>
#include <cppoptlib/problem.h>
#include <cppoptlib/solver/lbfgssolver.h>

#include <avogadro/core/contrastcolor.h>
#include <avogadro/core/vector.h>

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
#include <QPushButton>
#include <QSettings>
#include <QElapsedTimer>
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
}

AutoOpt::~AutoOpt() {}

void AutoOpt::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/autoopt.svg"));
  else
    m_activateAction->setIcon(QIcon(":/icons/autoopt.svg"));
}

void AutoOpt::setMolecule(QtGui::Molecule* mol)
{
  if (mol != nullptr) {
    m_molecule = mol->undoMolecule();
    // connect to any molecule changes
    connect(mol, SIGNAL(changed(unsigned int)),
            SLOT(moleculeChanged(unsigned int)));
  }
}

void AutoOpt::moleculeChanged(unsigned int changes)
{
  // qDebug() << "molecule changed" << changes;
  if (m_running && (changes != (Molecule::Atoms | Molecule::Moved))) {
    // restart
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

  m_method = Calc::EnergyManager::instance().model(m_currentMethod);

  if (m_method != nullptr) {
    m_method->setMolecule(&m_molecule->molecule());
    m_energy = calculateEnergy();
    m_deltaE = 0.0;
#ifndef NDEBUG
    qDebug() << "Initial energy:" << m_energy;
#endif
  }

  // start the optimization
  QElapsedTimer timer;
  timer.start();
  optimizeStep();
  qint64 minimumStep = 33; // 30 fps
  m_oneStepTime = std::max(timer.elapsed() + 5, minimumStep);

#ifndef NDEBUG
  qDebug() << QString("Finished in %L1 ms").arg(m_oneStepTime);
#endif
  m_timer.start(m_oneStepTime);

  emit drawablesChanged();
}

void AutoOpt::stop()
{
  // get the button from the widget
  QPushButton* startStopButton =
    m_toolWidget->findChild<QPushButton*>("startStopButton");
  startStopButton->setText(tr("Start"));
  startStopButton->setIcon(QIcon::fromTheme("go-down"));
  m_running = false;

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
    start();
  }
}

Real AutoOpt::calculateEnergy()
{
  int n = m_molecule->atomCount();
  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // now get the energy
  return m_method->value(positions);
}

void AutoOpt::optimizeStep()
{
  if (!m_running) {
    m_timer.stop();
    return;
  }

  int n = m_molecule->atomCount();
  // we have to cast the current 3d positions into a VectorXd
  Core::Array<Vector3> pos = m_molecule->atomPositions3d();
  double* p = pos[0].data();
  Eigen::Map<Eigen::VectorXd> map(p, 3 * n);
  Eigen::VectorXd positions = map;

  // get the frozen atoms
  auto mask = m_molecule->molecule().frozenAtomMask();
  if (mask.rows() != 3 * n) {
    mask = Eigen::VectorXd::Zero(3 * n);
    // set to 1.0
    for (Eigen::Index i = 0; i < 3 * n; ++i) {
      mask[i] = 1.0;
    }
  }
  m_method->setMask(mask);

  // optimize one step
  cppoptlib::LbfgsSolver<Calc::EnergyCalculator> solver;
  cppoptlib::Criteria<Real> crit = cppoptlib::Criteria<Real>::defaults();
  // e.g., every N steps, update coordinates
  crit.iterations = 2;
  solver.setStopCriteria(crit);

  solver.minimize(*m_method, positions);
  Real currentEnergy = m_method->value(positions);

  bool isFinite = std::isfinite(currentEnergy);
  if (isFinite) {
    m_deltaE = currentEnergy - m_energy; // should be negative = lower E

    const double* d = positions.data();
    [[maybe_unused]] bool allFinite = true;
    // casting back would be lovely...
    for (Index j = 0; j < n; ++j) {
      if (!std::isfinite(*d) || !std::isfinite(*(d + 1)) ||
          !std::isfinite(*(d + 2))) {
        allFinite = false;
        break;
      }

      pos[j] = Vector3(*(d), *(d + 1), *(d + 2));
      d += 3;
    }

    // todo - merge these into one undo step
    if (allFinite) {
      m_molecule->setAtomPositions3d(pos, tr("Optimize Geometry"));
      Molecule::MoleculeChanges changes = Molecule::Atoms | Molecule::Moved;
      m_molecule->emitChanged(changes);
    }
  }
}

void AutoOpt::draw(Rendering::GroupNode& node)
{
  if (!m_running)
    return; // nothing to draw

  QString overlayText;
  overlayText = tr("%1 ΔE = %L2 kcal/mol")
                  .arg(m_currentMethod.c_str())
                  .arg(m_deltaE, 0, 'f', 2);

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
