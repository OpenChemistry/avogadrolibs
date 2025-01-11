/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_VIBRATIONS_H
#define AVOGADRO_QTPLUGINS_VIBRATIONS_H

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
  QList<QAction*> m_actions;

  QtGui::Molecule* m_molecule;

  VibrationDialog* m_dialog;

  QTimer* m_timer;

  int m_currentFrame;
  int m_totalFrames;
  int m_mode;
  int m_amplitude;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_VIBRATIONS_H
