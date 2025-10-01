/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "autoopt.h"

#include <avogadro/calc/energymanager.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

#include <QAction>
#include <QFormLayout>
#include <QComboBox>
#include <QPushButton>
#include <QtGui/QIcon>
#include <QtGui/QKeyEvent>
#include <QtGui/QMouseEvent>
#include <QtGui/QWheelEvent>

#include <QDebug>

using Avogadro::QtGui::Molecule;

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
    tr("Auto Optimize Tool \t(%1)\n\n"
       "Navigation Functions when clicking in empty space.\n"
       "Left Mouse: \tRotate Space\n"
       "Middle Mouse: \tZoom Space\n"
       "Right Mouse: \tMove Space\n"
       "Double-Click: \tReset View\n\n"
       "When running:\n"
       "Left Mouse: \tClick and drag atoms to move them.")
      .arg(shortcut));
  setIcon();
}

AutoOpt::~AutoOpt() {}

void AutoOpt::setIcon(bool darkTheme)
{
  if (darkTheme)
    m_activateAction->setIcon(QIcon(":/icons/autoopt_dark.png"));
  else
    m_activateAction->setIcon(QIcon(":/icons/autoopt_light.png"));
}

void AutoOpt::setMolecule(QtGui::Molecule* mol)
{
  if (mol)
    m_molecule = mol->undoMolecule();
  // connect to any molecule changes
  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));
}

void AutoOpt::moleculeChanged(unsigned int)
{
  stop();
  // should also restart
}

QWidget* AutoOpt::toolWidget() const
{
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
    auto recommended = Calc::EnergyManager::instance().recommendedModel(mol);
    methodComboBox->setCurrentIndex(
      methodComboBox->findText(recommended.c_str()));
    connect(methodComboBox, &QComboBox::currentTextChanged, this,
            &AutoOpt::methodChanged);
    form->addRow(tr("Method:"), methodComboBox);

    // start stop button
    QPushButton* startStopButton = new QPushButton(tr("Start"));
    startStopButton->setObjectName("startStopButton");
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
  m_running = true;
}

void AutoOpt::stop()
{
  // get the button from the widget
  QPushButton* startStopButton =
    m_toolWidget->findChild<QPushButton*>("startStopButton");
  startStopButton->setText(tr("Start"));
  m_running = false;
}

void AutoOpt::methodChanged(const QString& method)
{
  qDebug() << " changing method " << method;
  m_currentMethod = method.toStdString();

  // need to stop, then restart after a brief pause
  stop();
  start();
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
}

} // namespace Avogadro::QtPlugins
