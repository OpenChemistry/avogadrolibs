/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrations.h"
#include "vibrationdialog.h"

#include <avogadro/core/array.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

namespace Avogadro::QtPlugins {

Vibrations::Vibrations(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_timer(nullptr), m_mode(0), m_amplitude(20)
{
  auto* action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Vibrational Modes…"));
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);
}

Vibrations::~Vibrations() {}

QList<QAction*> Vibrations::actions() const
{
  return m_actions;
}

QStringList Vibrations::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analyze");
  return path;
}

void Vibrations::setMolecule(QtGui::Molecule* mol)
{
  if (mol == nullptr)
    return;

  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  bool isVibrational(false);
  if (mol->vibrationFrequencies().size())
    isVibrational = true;

  m_actions[0]->setEnabled(isVibrational);
  m_molecule = mol;
  if (m_dialog)
    m_dialog->setMolecule(mol);

  if (isVibrational)
    openDialog();

  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));
}

void Vibrations::moleculeChanged([[maybe_unused]] unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  bool currentVibrational = m_actions[0]->isEnabled();
  bool isVibrational = (m_molecule->vibrationFrequencies().size() > 0);

  if (currentVibrational != isVibrational) {
    m_actions[0]->setEnabled(isVibrational);
    if (m_dialog)
      m_dialog->setMolecule(m_molecule); // update the dialog
    if (isVibrational)
      openDialog();
  }
}

void Vibrations::registerCommands()
{
  emit registerCommand("showVibrations",
                       tr("Show the vibrational modes dialog."));
  emit registerCommand("setVibrationalMode", tr("Set the vibrational mode."));
  emit registerCommand("setVibrationalAmplitude",
                       tr("Set the vibrational amplitude."));
  emit registerCommand("startVibrationAnimation",
                       tr("Start the vibrational animation."));
  emit registerCommand("stopVibrationAnimation",
                       tr("Stop the vibrational animation."));
}

bool Vibrations::handleCommand(const QString& command,
                               const QVariantMap& options)
{
  if (m_molecule == nullptr)
    return false; // No molecule to handle the command.

  if (command == "showVibrations") {
    openDialog();
    return true;
  } else if (command == "setVibrationalMode") {
    if (options.contains("mode")) {
      setMode(options["mode"].toInt());
      return true;
    }
  } else if (command == "setVibrationalAmplitude") {
    if (options.contains("amplitude")) {
      setAmplitude(options["amplitude"].toInt());
      return true;
    }
  } else if (command == "startVibrationAnimation") {
    startVibrationAnimation();
    return true;
  } else if (command == "stopVibrationAnimation") {
    stopVibrationAnimation();
    return true;
  }
  return false;
}

void Vibrations::setMode(int mode)
{
  if (mode >= 0 &&
      mode < static_cast<int>(m_molecule->vibrationFrequencies().size())) {
    m_mode = mode;

    // Now calculate the frames and set them on the molecule.
    m_molecule->setCoordinate3d(0);
    Core::Array<Vector3> atomPositions = m_molecule->atomPositions3d();
    Core::Array<Vector3> atomDisplacements = m_molecule->vibrationLx(mode);
    // TODO: needs an option (show forces or not)
    double factor = 0.01 * m_amplitude;
    Index atom = 0;
    for (Vector3& v : atomDisplacements) {
      v *= 10.0 * factor;
      m_molecule->setForceVector(atom, v);
      ++atom;
    }

    int frames = 5; // TODO: needs an option
    int frameCounter = 0;
    m_molecule->clearCoordinate3d();
    m_molecule->setCoordinate3d(atomPositions, frameCounter++);

    // Current coords + displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] + atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // + displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] + atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // Current coords - displacement.
    for (int i = 1; i <= frames; ++i) {
      Core::Array<Vector3> framePositions;
      for (atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] - atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
    // - displacement back to original.
    for (int i = frames - 1; i >= 0; --i) {
      Core::Array<Vector3> framePositions;
      for (atom = 0; atom < m_molecule->atomCount(); ++atom) {
        framePositions.push_back(atomPositions[atom] - atomDisplacements[atom] *
                                                         factor *
                                                         (double(i) / frames));
      }
      m_molecule->setCoordinate3d(framePositions, frameCounter++);
    }
  }
}

void Vibrations::setAmplitude(int amplitude)
{
  m_amplitude = amplitude;
  setMode(m_mode);
}

void Vibrations::startVibrationAnimation()
{
  // First calculate our frames, and then start our timer.
  m_totalFrames = m_molecule->coordinate3dCount();
  m_currentFrame = 0;

  if (!m_timer) {
    m_timer = new QTimer(this);
    connect(m_timer, SIGNAL(timeout()), SLOT(advanceFrame()));
  }
  if (!m_timer->isActive()) {
    m_timer->start(50);
  }
}

void Vibrations::stopVibrationAnimation()
{
  if (m_timer && m_timer->isActive()) {
    m_timer->stop();
    m_molecule->setCoordinate3d(0);
    m_currentFrame = 0;
    m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
  }
}

void Vibrations::openDialog()
{
  if (!m_dialog) {
    m_dialog = new VibrationDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, SIGNAL(modeChanged(int)), SLOT(setMode(int)));
    connect(m_dialog, SIGNAL(amplitudeChanged(int)), SLOT(setAmplitude(int)));
    connect(m_dialog, SIGNAL(startAnimation()),
            SLOT(startVibrationAnimation()));
    connect(m_dialog, SIGNAL(stopAnimation()), SLOT(stopVibrationAnimation()));
  }
  if (m_molecule)
    m_dialog->setMolecule(m_molecule);
  m_dialog->show();
}

void Vibrations::advanceFrame()
{
  if (++m_currentFrame >= m_totalFrames)
    m_currentFrame = 0;
  m_molecule->setCoordinate3d(m_currentFrame);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
}
} // namespace Avogadro::QtPlugins
