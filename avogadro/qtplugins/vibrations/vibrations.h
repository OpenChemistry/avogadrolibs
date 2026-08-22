/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONS_H
#define AVOGADRO_QTPLUGINS_VIBRATIONS_H

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;
class QTimer;

namespace Avogadro {

namespace QtPlugins {

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
  void startVibrationAnimation();
  void stopVibrationAnimation();
  void openDialog();
  void moleculeChanged(unsigned int changes);

private slots:
  void advanceFrame();

private:
  /** Stop any running animation and discard its frames. */
  void resetAnimation();

  /**
   * Rebuild the dialog's mode table for the active conformer. Records which
   * conformer it was built for so playback, which signals a conformer change
   * on every frame, does not rebuild it repeatedly.
   */
  void reloadDialog();

  /** @return True if the active conformer index refers to a coordinate set. */
  bool activeConformerIsStored() const;

  /**
   * Put back the undisplaced geometry the animation was drawn on top of, and
   * reset the frame counter.
   */
  void restoreRestGeometry();

  QList<QAction*> m_actions;

  QtGui::Molecule* m_molecule;

  VibrationDialog* m_dialog;

  QTimer* m_timer;

  /**
   * The displaced geometries the animation cycles through. These are held
   * here rather than pushed into the molecule's coordinate sets, which would
   * destroy any trajectory or reaction path that was loaded from the file.
   */
  Core::Array<Core::Array<Vector3>> m_animationFrames;

  /** The conformer the dialog's mode table was last built for, -1 if none. */
  int m_dialogConformer = -1;

  int m_currentFrame = 0;
  int m_mode;
  int m_amplitude;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VIBRATIONS_H
