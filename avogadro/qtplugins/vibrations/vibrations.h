/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONS_H
#define AVOGADRO_QTPLUGINS_VIBRATIONS_H

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QList>

class QAction;
class QDialog;
class QTimer;

namespace Avogadro::QtPlugins {

class VibrationDialog;

/**
 * @brief The Vibration plugin handles vibration animations.
 */

class Vibrations : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Vibrations(QObject* parent = nullptr);
  ~Vibrations() override;

  QString name() const override { return tr("Vibrations"); }

  QString description() const override
  {
    return tr("Display vibrational modes.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  void registerCommands() override;

public slots:
  void setMode(int mode);
  void setAmplitude(int amplitude);

  /** Set the number of frames in one vibration cycle (clamped to 4-200). */
  void setFramesPerCycle(int frames);

  /** Make @p frame (zero-based) the active coordinate set. */
  void goToFrame(int frame);
  void startVibrationAnimation();
  void stopVibrationAnimation();
  void openDialog();
  void moleculeChanged(unsigned int changes);

  /**
   * Append new coordinate sets displaced along @p modes, which are summed and
   * scaled by @p scale. @p structures == 1 generates a single geometry at
   * @p scale; more are spread evenly over [-scale, +scale]. The first new set
   * becomes the active one.
   */
  void generateDisplacedCoordinates(const QList<int>& modes, double scale,
                                    int structures);

private slots:
  void advanceFrame();

  /** Stop our animation if another animator took over the display. */
  void animationPlaybackClaimed(QObject* owner);

private:
  /** Stop the timer and put the dialog's button back to "start". */
  void stopTimer();

  /**
   * Stop any running animation and withdraw the published frames, which also
   * puts the rest positions back if one of them is on screen.
   */
  void resetAnimation();

  /**
   * Re-evaluate the modes for the active conformer: the action state, the
   * default mode, the published frames and the dialog. Never shows the dialog.
   */
  void refreshModes();

  /** @return The mode to select by default: the first above 0.5 cm^-1. */
  int defaultMode() const;

  /**
   * Publish @p frames for the Animation tool, replacing the current set. An
   * empty array, or an active frame without modes, withdraws the set.
   */
  void publishFrames(const Core::Array<Core::Array<Vector3>>& frames);

  /**
   * Bring the dialog (if it exists) in step with the active conformer: the
   * mode table, the selected mode, the controls, or the page pointing at the
   * frames that do have modes. Does not show it.
   */
  void reloadDialog();

  /**
   * @return True if the active conformer index refers to a coordinate set.
   * @note m_molecule must not be null; the callers check that first.
   */
  bool activeConformerIsStored() const;

  /**
   * @return The geometry the normal modes belong to, which is not necessarily
   * what is on screen: while an animation is running the displayed positions
   * are a displaced frame.
   * @note m_molecule must not be null; the callers check that first.
   */
  Core::Array<Vector3> restGeometry() const;

  QList<QAction*> m_actions;

  QtGui::Molecule* m_molecule;

  VibrationDialog* m_dialog;

  QTimer* m_timer;

  /** The conformer the current mode was chosen for, -1 if none. */
  int m_modeConformer = -1;

  /** True if the active conformer has vibrational modes. */
  bool m_haveModes = false;

  int m_framesPerCycle = 20;

  int m_currentFrame = 0;
  int m_mode;
  int m_amplitude;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_VIBRATIONS_H
