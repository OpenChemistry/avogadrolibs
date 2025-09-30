/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SPECTRA_H
#define AVOGADRO_QTPLUGINS_SPECTRA_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtPlugins {

class SpectraDialog;

/**
 * @brief The Spectra plugin handles vibrations and spectra.
 */

class Spectra : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Spectra(QObject* parent = nullptr);
  ~Spectra() override = default;

  QString name() const override { return tr("Spectra"); }

  QString description() const override { return tr("Display spectra plots."); }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:

  void openDialog();
  void moleculeChanged(unsigned int changes);

private:
  void gatherSpectra();

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  SpectraDialog* m_dialog;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_Spectra_H
