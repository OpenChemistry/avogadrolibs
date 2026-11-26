/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrations.h"
#include "vibrationdialog.h"
#include "vibrationframes.h"

#include <avogadro/core/array.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

#include <algorithm>
#include <cmath>
#include <vector>

namespace Avogadro::QtPlugins {

Vibrations::Vibrations(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_timer(nullptr), m_mode(0), m_amplitude(20)
{
  auto* action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Vibrational Modes…"));
  connect(action, &QAction::triggered, this, &Vibrations::openDialog);
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

  if (m_molecule != nullptr) {
    // Frames belong to the molecule they were built from.
    resetAnimation();
    m_molecule->disconnect(this);
  }

  m_molecule = mol;
  m_modeConformer = -1; // force the modes to be re-read for the new molecule
  refreshModes();

  connect(m_molecule, &QtGui::Molecule::changed, this,
          &Vibrations::moleculeChanged);
  connect(m_molecule, &QtGui::Molecule::animationPlaybackClaimed, this,
          &Vibrations::animationPlaybackClaimed);

  // Only a freshly loaded molecule opens the dialog, and only if there is
  // something to show.
  if (m_molecule->hasAnyVibrations())
    openDialog();
}

void Vibrations::stopTimer()
{
  if (m_timer && m_timer->isActive()) {
    m_timer->stop();
    if (m_dialog)
      m_dialog->resetAnimationButton();
  }
}

void Vibrations::resetAnimation()
{
  stopTimer();
  m_currentFrame = 0;
  // Withdrawing the set also puts back the rest positions if it was shown.
  if (m_molecule)
    m_molecule->removeAnimationFrames(QStringLiteral("vibration"));
}

int Vibrations::defaultMode() const
{
  const Core::Array<double> freqs = m_molecule->vibrationFrequencies();
  for (size_t i = 0; i < freqs.size(); ++i) {
    if (freqs[i] > 0.5)
      return static_cast<int>(i);
  }
  return 0;
}

void Vibrations::refreshModes()
{
  if (m_molecule == nullptr)
    return;

  m_modeConformer = m_molecule->coordinate3d();
  m_actions[0]->setEnabled(m_molecule->hasAnyVibrations());

  // The frames were built from the previous conformer's geometry and modes.
  // The published set stays up until it is replaced or withdrawn below, so
  // the Animation tool does not see the source vanish and reappear. The
  // molecule has already dropped any displayed frame on a conformer change.
  stopTimer();
  m_currentFrame = 0;

  m_haveModes = m_molecule->hasVibrations();
  if (m_haveModes) {
    m_mode = defaultMode();
    setMode(m_mode);
  } else {
    publishFrames(Core::Array<Core::Array<Vector3>>());
  }
  reloadDialog();
}

void Vibrations::reloadDialog()
{
  // A hidden dialog catches up in openDialog(), so playback over a trajectory
  // does not rebuild it on every frame.
  if (m_dialog == nullptr || m_molecule == nullptr || !m_dialog->isVisible())
    return;

  if (m_haveModes || !m_molecule->hasAnyVibrations()) {
    m_dialog->setMolecule(m_molecule);
    m_dialog->showModes();
    m_dialog->setAmplitude(m_amplitude);
    m_dialog->setFramesPerCycle(m_framesPerCycle);
    if (m_haveModes)
      m_dialog->setCurrentMode(m_mode);
    return;
  }

  // The active frame has no modes, but others do. The table is hidden, so it
  // is not rebuilt.
  std::vector<int> frames;
  for (size_t conformer : m_molecule->vibrationConformers())
    frames.push_back(static_cast<int>(conformer));
  m_dialog->showNoModes(
    frames, nearestVibrationFrame(frames, m_molecule->coordinate3d()));
}

void Vibrations::moleculeChanged(unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  // A trajectory with no vibrations anywhere has nothing to follow, and this
  // runs on every playback frame.
  if (!m_haveModes && !m_actions[0]->isEnabled() &&
      !m_molecule->hasAnyVibrations())
    return;

  // A file can carry a Hessian at more than one geometry, so the modes belong
  // to the active conformer and have to be re-read when it changes. Compare
  // the index rather than trusting the flag alone: the flag tells us to look,
  // but playback re-emits it for every frame of the same conformer. A
  // structural edit discards or replaces the modes without moving to another
  // conformer.
  const bool conformerChanged = (changes & QtGui::Molecule::Conformer) != 0 &&
                                m_molecule->coordinate3d() != m_modeConformer;
  const bool structureChanged =
    QtGui::Molecule::invalidatesDerivedData(changes);

  if (conformerChanged || structureChanged ||
      m_haveModes != m_molecule->hasVibrations() ||
      m_actions[0]->isEnabled() != m_molecule->hasAnyVibrations()) {
    // Never raise or show the dialog from here: this runs on every playback
    // frame.
    refreshModes();
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
  static const QStringList knownCommands = {
    "showVibrations",          "setVibrationalMode",
    "setVibrationalAmplitude", "startVibrationAnimation",
    "stopVibrationAnimation",  "generateDisplacedCoordinates"
  };

  if (!knownCommands.contains(command))
    return false; // not one of our commands

  if (m_molecule == nullptr) {
    emit commandFailed(tr("No molecule"));
    return true;
  }

  if (command == "showVibrations") {
    if (!m_molecule->hasAnyVibrations()) {
      emit commandFailed(tr("No vibrational modes"));
      return true;
    }
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
  if (atomDisplacements.size() != atomPositions.size()) {
    publishFrames(Core::Array<Core::Array<Vector3>>());
    return;
  }

  // TODO: needs an option (show forces or not)
  // The arrows are lx * 0.1 * amplitude.
  const double forceScale = 0.1 * m_amplitude;
  Index atom = 0;
  for (const Vector3& v : atomDisplacements) {
    m_molecule->setForceVector(atom, v * forceScale);
    ++atom;
  }

  // Publish the displaced geometries as a frame set. Writing them into the
  // molecule's coordinate sets would overwrite a loaded trajectory or
  // reaction path, and make the conformer-aware UI count them as conformers.
  // The peak displacement is lx * 0.001 * amplitude^2: the amplitude enters
  // twice, as it has since 2.0 (the force vectors above scale only once).
  const double peakScale = 0.001 * m_amplitude * m_amplitude;
  publishFrames(vibrationFrames(atomPositions, atomDisplacements, peakScale,
                                m_framesPerCycle));

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
  // equilibrium geometry. With no coordinate sets the molecule remembers the
  // positions that were on screen before the first frame was shown.
  if (activeConformerIsStored())
    return m_molecule->coordinate3d(m_molecule->coordinate3d());
  return m_molecule->restPositions3d();
}

void Vibrations::setAmplitude(int amplitude)
{
  m_amplitude = amplitude;
  setMode(m_mode);
}

void Vibrations::setFramesPerCycle(int frames)
{
  m_framesPerCycle = std::clamp(frames, 4, 200);
  setMode(m_mode);
}

void Vibrations::goToFrame(int frame)
{
  if (m_molecule == nullptr || frame < 0 ||
      frame >= static_cast<int>(m_molecule->coordinate3dCount()))
    return;

  // The conformer plot and the Animation tool follow the Conformer flag.
  m_molecule->setCoordinate3d(frame);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Moved |
                          QtGui::Molecule::Conformer);
}

void Vibrations::publishFrames(const Core::Array<Core::Array<Vector3>>& frames)
{
  if (m_molecule == nullptr)
    return;
  if (frames.empty() || !m_molecule->hasVibrations()) {
    m_molecule->removeAnimationFrames(QStringLiteral("vibration"));
    return;
  }

  const Core::Array<double> freqs = m_molecule->vibrationFrequencies();
  const double frequency =
    m_mode >= 0 && m_mode < static_cast<int>(freqs.size()) ? freqs[m_mode]
                                                           : 0.0;
  m_molecule->setAnimationFrames(
    QStringLiteral("vibration"),
    tr("Vibration: mode %1, %2 cm⁻¹").arg(m_mode + 1).arg(frequency, 0, 'f', 1),
    frames);
}

void Vibrations::animationPlaybackClaimed(QObject* owner)
{
  if (owner == this)
    return;

  // The claimer is about to display its own frame, so leave the geometry
  // alone.
  stopTimer();
  m_currentFrame = 0;
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

  // The frames were published by setMode(). Nothing to animate without them.
  if (m_molecule->animationFrameCount(QStringLiteral("vibration")) == 0)
    setMode(m_mode);
  if (m_molecule->animationFrameCount(QStringLiteral("vibration")) == 0)
    return;

  m_currentFrame = 0;
  m_molecule->claimAnimationPlayback(this);

  if (!m_timer) {
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &Vibrations::advanceFrame);
  }
  if (!m_timer->isActive()) {
    m_timer->start(50);
  }
}

void Vibrations::stopVibrationAnimation()
{
  if (m_timer && m_timer->isActive()) {
    stopTimer();
    m_currentFrame = 0;
    // Put the geometry back, unless the Animation tool has taken over.
    if (m_molecule &&
        m_molecule->shownAnimationId() == QLatin1String("vibration"))
      m_molecule->clearAnimationDisplay();
  }
}

void Vibrations::openDialog()
{
  if (!m_dialog) {
    m_dialog = new VibrationDialog(qobject_cast<QWidget*>(parent()));
    connect(m_dialog, &VibrationDialog::modeChanged, this,
            &Vibrations::setMode);
    connect(m_dialog, &VibrationDialog::amplitudeChanged, this,
            &Vibrations::setAmplitude);
    connect(m_dialog, &VibrationDialog::framesPerCycleChanged, this,
            &Vibrations::setFramesPerCycle);
    connect(m_dialog, &VibrationDialog::goToFrame, this,
            &Vibrations::goToFrame);
    connect(m_dialog, &VibrationDialog::startAnimation, this,
            &Vibrations::startVibrationAnimation);
    connect(m_dialog, &VibrationDialog::stopAnimation, this,
            &Vibrations::stopVibrationAnimation);
    // Checked at compile time: the old-style macro form cannot verify a
    // signature carrying a template argument.
    connect(m_dialog, &VibrationDialog::generateDisplacedCoordinates, this,
            &Vibrations::generateDisplacedCoordinates);
  }
  // Show first: reloadDialog() skips a hidden dialog.
  m_dialog->show();
  reloadDialog();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void Vibrations::advanceFrame()
{
  if (m_molecule == nullptr)
    return;

  const QString id = QStringLiteral("vibration");
  const auto count = static_cast<int>(m_molecule->animationFrameCount(id));
  if (count == 0)
    return;

  if (++m_currentFrame >= count)
    m_currentFrame = 0;

  // The molecule puts the frame on screen and remembers the rest positions,
  // leaving the coordinate sets alone.
  m_molecule->showAnimationFrame(id, static_cast<size_t>(m_currentFrame));
}
} // namespace Avogadro::QtPlugins
