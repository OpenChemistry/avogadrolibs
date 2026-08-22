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

  m_molecule = mol;
  // Frames belong to the molecule they were built from.
  resetAnimation();
  m_dialogConformer = -1; // force the table to rebuild for the new molecule

  bool isVibrational = mol->hasVibrations();

  m_actions[0]->setEnabled(isVibrational);
  if (m_dialog)
    reloadDialog();

  if (isVibrational)
    openDialog();

  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));
}

void Vibrations::resetAnimation()
{
  if (m_timer && m_timer->isActive()) {
    m_timer->stop();
    if (m_dialog)
      m_dialog->resetAnimationButton();
  }
  m_animationFrames.clear();
  m_currentFrame = 0;
}

void Vibrations::reloadDialog()
{
  if (m_dialog == nullptr || m_molecule == nullptr)
    return;

  // setMolecule() rebuilds the mode table and re-selects a mode, so only call
  // it when the modes on show are actually stale. Trajectory playback emits a
  // conformer change on every frame, and rebuilding the table there was both
  // wasted work and a visible flicker.
  m_dialogConformer = m_molecule->coordinate3d();
  m_dialog->setMolecule(m_molecule);
}

void Vibrations::moleculeChanged(unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  // A file can carry a Hessian at more than one geometry, so the modes belong
  // to the active conformer and have to be re-read when it changes. Compare
  // the index rather than trusting the flag alone: the flag tells us to look,
  // but playback re-emits it for every frame of the same conformer, and a
  // caller that forgets it would otherwise leave the table stale.
  const bool conformerChanged = (changes & QtGui::Molecule::Conformer) != 0 &&
                                m_molecule->coordinate3d() != m_dialogConformer;

  if (conformerChanged) {
    // The frames were built from the previous conformer's geometry and modes.
    // Drop them rather than restoring that geometry: whoever changed the
    // conformer meant to move away from it.
    resetAnimation();
  }

  bool currentVibrational = m_actions[0]->isEnabled();
  bool isVibrational = m_molecule->hasVibrations();

  if (currentVibrational != isVibrational) {
    m_actions[0]->setEnabled(isVibrational);
    reloadDialog();
    if (isVibrational)
      openDialog();
  } else if (conformerChanged && isVibrational) {
    // Same enabled state, different modes: reload the table for this
    // conformer. This re-selects a mode, which rebuilds the frames.
    reloadDialog();
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
  if (m_molecule == nullptr)
    return;

  if (mode < 0 ||
      mode >= static_cast<int>(m_molecule->vibrationFrequencies().size()))
    return;

  m_mode = mode;

  // Animate around the geometry the user is looking at. The displacements
  // belong to the active conformer, so do not switch conformers here.
  //
  // Take the rest geometry from the stored coordinate set, not from the
  // displayed positions: while an animation is running those are a displaced
  // frame, and building the next set of frames on them would make the
  // molecule walk away from its equilibrium geometry on every amplitude
  // change. Frame 0 is the rest geometry when there are no coordinate sets.
  Core::Array<Vector3> atomPositions;
  if (activeConformerIsStored()) {
    atomPositions = m_molecule->coordinate3d(m_molecule->coordinate3d());
  } else if (!m_animationFrames.empty()) {
    atomPositions = m_animationFrames[0];
  } else {
    atomPositions = m_molecule->atomPositions3d();
  }

  Core::Array<Vector3> atomDisplacements = m_molecule->vibrationLx(mode);

  // A mode with the wrong number of displacements cannot be animated, and
  // indexing it per atom below would run off the end.
  if (atomDisplacements.size() != atomPositions.size())
    return;

  // TODO: needs an option (show forces or not)
  double factor = 0.01 * m_amplitude;
  Index atom = 0;
  for (Vector3& v : atomDisplacements) {
    v *= 10.0 * factor;
    m_molecule->setForceVector(atom, v);
    ++atom;
  }

  // Build the displaced geometries in our own buffer. Writing them into the
  // molecule's coordinate sets would overwrite a loaded trajectory or
  // reaction path, and make the conformer-aware UI count them as conformers.
  const int frames = 5; // TODO: needs an option
  m_animationFrames.clear();

  // One cycle: 0 -> +max -> 0 -> -max -> 0, sampled at `frames` steps per leg.
  auto appendFrame = [&](double scale) {
    Core::Array<Vector3> framePositions;
    framePositions.reserve(atomPositions.size());
    for (Index i = 0; i < atomPositions.size(); ++i)
      framePositions.push_back(atomPositions[i] +
                               atomDisplacements[i] * factor * scale);
    m_animationFrames.push_back(framePositions);
  };

  appendFrame(0.0);
  for (int i = 1; i <= frames; ++i) // out along +displacement
    appendFrame(double(i) / frames);
  for (int i = frames - 1; i >= 0; --i) // back to the original geometry
    appendFrame(double(i) / frames);
  for (int i = 1; i <= frames; ++i) // out along -displacement
    appendFrame(-double(i) / frames);
  for (int i = frames - 1; i >= 0; --i) // and back again
    appendFrame(-double(i) / frames);

  m_currentFrame = 0;

  // The force vectors changed, and any running animation is now showing the
  // previous mode's geometry.
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Moved);
}

bool Vibrations::activeConformerIsStored() const
{
  const int active = m_molecule->coordinate3d();
  return active >= 0 &&
         active < static_cast<int>(m_molecule->coordinate3dCount());
}

void Vibrations::restoreRestGeometry()
{
  m_currentFrame = 0;
  if (m_molecule == nullptr)
    return;

  // Put back the geometry the animation was drawn on top of. The animation
  // never changed the active conformer, so re-reading it here is the same
  // index setMode() built the frames from.
  if (activeConformerIsStored()) {
    m_molecule->setCoordinate3d(m_molecule->coordinate3d());
  } else if (!m_animationFrames.empty()) {
    // No coordinate sets at all (a plain frequency calculation): frame 0 is
    // the undisplaced geometry.
    m_molecule->setAtomPositions3d(m_animationFrames[0]);
  }

  // Only the displayed positions moved: the animation never changed the
  // active conformer, so this is not a Conformer change and must not make the
  // dialog rebuild its mode table.
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Moved);
}

void Vibrations::setAmplitude(int amplitude)
{
  m_amplitude = amplitude;
  setMode(m_mode);
}

void Vibrations::startVibrationAnimation()
{
  if (m_molecule == nullptr)
    return;

  // The frames were built by setMode(). Nothing to animate without them.
  if (m_animationFrames.empty())
    setMode(m_mode);
  if (m_animationFrames.empty())
    return;

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
    // Restore the geometry we were animating, not a hardcoded frame 0.
    restoreRestGeometry();
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
  reloadDialog();
  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void Vibrations::advanceFrame()
{
  if (m_molecule == nullptr || m_animationFrames.empty())
    return;

  if (++m_currentFrame >= static_cast<int>(m_animationFrames.size()))
    m_currentFrame = 0;

  // Display the displaced geometry without disturbing the coordinate sets.
  m_molecule->setAtomPositions3d(m_animationFrames[m_currentFrame]);
  // Use Moved flag for coordinate changes, not Added (which implies new atoms)
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Moved);
}
} // namespace Avogadro::QtPlugins
