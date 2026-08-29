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

#include <cmath>

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
  emit registerCommand(
    "generateDisplacedCoordinates",
    tr("Add coordinate sets displaced along one or more vibrational modes."));
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
  } else if (command == "generateDisplacedCoordinates") {
    QList<int> modes;
    if (options.contains("modes")) {
      const QVariantList list = options["modes"].toList();
      for (const QVariant& mode : list)
        modes.append(mode.toInt());
    } else if (options.contains("mode")) {
      modes.append(options["mode"].toInt());
    }
    if (modes.isEmpty())
      return false;

    const double scale =
      options.contains("scale") ? options["scale"].toDouble() : 1.0;
    const int structures =
      options.contains("structures") ? options["structures"].toInt() : 1;
    // Report a scale that cannot displace anything as unhandled, rather than
    // returning success for a call that does nothing.
    if (std::fabs(scale) < 1e-9 || structures < 1)
      return false;

    generateDisplacedCoordinates(modes, scale, structures);
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
  Core::Array<Vector3> atomPositions = restGeometry();

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

Core::Array<Vector3> Vibrations::restGeometry() const
{
  // Take the rest geometry from the stored coordinate set, not from the
  // displayed positions: while an animation is running those are a displaced
  // frame, and building on them would make the molecule walk away from its
  // equilibrium geometry. Frame 0 is the rest geometry when there are no
  // coordinate sets.
  if (activeConformerIsStored())
    return m_molecule->coordinate3d(m_molecule->coordinate3d());
  if (!m_animationFrames.empty())
    return m_animationFrames[0];
  return m_molecule->atomPositions3d();
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

void Vibrations::generateDisplacedCoordinates(const QList<int>& modes,
                                              double scale, int structures)
{
  // A zero scale factor would append copies of the geometry that is already
  // there. The dialog refuses it, but this slot is also reachable as a
  // command.
  if (m_molecule == nullptr || modes.isEmpty() || structures < 1 ||
      std::fabs(scale) < 1e-9)
    return;

  // Displace the geometry the modes belong to, which is not what is on screen
  // while an animation is running. Read it before resetting the animation,
  // which discards the frames it may have come from.
  const Core::Array<Vector3> base = restGeometry();
  if (base.empty())
    return;

  // Sum the selected modes into a single displacement. Read them before
  // anything below changes which conformer is active, since the modes are
  // stored per conformer.
  Core::Array<Vector3> displacement(base.size(), Vector3::Zero());
  for (int mode : modes) {
    const Core::Array<Vector3> lx = m_molecule->vibrationLx(mode);
    // A mode with the wrong number of displacements cannot be applied, and
    // indexing it per atom would run off the end.
    if (lx.size() != base.size())
      return;
    for (Index i = 0; i < base.size(); ++i)
      displacement[i] += lx[i];
  }

  resetAnimation();

  // A plain frequency calculation has no coordinate sets at all. Store the
  // geometry the modes belong to as set 0, so it stays reachable once the
  // displaced sets are added -- and so the vibrational data, which is keyed
  // on the coordinate set index, stays attached to it.
  if (m_molecule->coordinate3dCount() == 0)
    m_molecule->setCoordinate3d(base, 0);

  const size_t first = m_molecule->coordinate3dCount();
  for (int step = 0; step < structures; ++step) {
    // A single structure sits at the requested scale; several are spread
    // evenly over [-scale, +scale], so an odd count includes the undisplaced
    // geometry in the middle.
    const double factor =
      structures == 1
        ? scale
        : -scale + 2.0 * scale * step / static_cast<double>(structures - 1);

    Core::Array<Vector3> positions;
    positions.reserve(base.size());
    for (Index i = 0; i < base.size(); ++i)
      positions.push_back(base[i] + displacement[i] * factor);
    m_molecule->setCoordinate3d(positions, first + step);
  }

  // The new sets deliberately carry no vibrational data: the modes belong to
  // the geometry they were computed at, and a displaced structure is not that
  // geometry. The mode table empties until the user steps back to the
  // conformer the Hessian came from.
  m_molecule->setCoordinate3d(static_cast<int>(first));

  // The arrows were drawn for the mode being animated at the old geometry.
  m_molecule->setForceVectors(Core::Array<Vector3>());

  // Atoms moved and the active set changed, but pair this with Moved rather
  // than Modified: Modified would have emitChanged() discard the vibrational
  // data we just took care to keep. See Molecule::invalidatesDerivedData().
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Moved |
                          QtGui::Molecule::Conformer);
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
    // Checked at compile time: the old-style macro form cannot verify a
    // signature carrying a template argument.
    connect(m_dialog, &VibrationDialog::generateDisplacedCoordinates, this,
            &Vibrations::generateDisplacedCoordinates);
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
