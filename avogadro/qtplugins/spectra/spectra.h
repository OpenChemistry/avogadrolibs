/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPECTRA_H
#define AVOGADRO_QTPLUGINS_SPECTRA_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;
class QTimer;

namespace Avogadro {
namespace QtPlugins {

class VibrationDialog;

/**
 * @brief The Spectra plugin handles vibrations and spectra.
 */

class Spectra : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Spectra(QObject* parent = nullptr);
  ~Spectra() override;

  QString name() const override { return tr("Spectra and Vibrations"); }

  QString description() const override
  {
    return tr("Display spectra and vibrational modes.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  void setMode(int mode);
  void setAmplitude(int amplitude);
  void startVibrationAnimation();
  void stopVibrationAnimation();
  void openDialog();

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
}
}

#endif // AVOGADRO_QTPLUGINS_Spectra_H
