/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "spectra.h"
#include "spectradialog.h"

#include <avogadro/core/array.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/qtgui/chartdialog.h>
#include <avogadro/qtgui/chartwidget.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

namespace Avogadro::QtPlugins {

Spectra::Spectra(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr)
{
  auto* action = new QAction(this);
  action->setEnabled(false);
  action->setText(tr("Plot Spectra…"));
  action->setProperty("menu priority", -900);
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);
}

QList<QAction*> Spectra::actions() const
{
  return m_actions;
}

QStringList Spectra::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analyze");
  return path;
}

void Spectra::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  // extract vibrational and other spectra
  m_molecule = mol;

  if (m_molecule == nullptr) {
    return;
  }

  bool enableAction = false;
  // check to see if it has IR or Raman data
  if (!m_molecule->vibrationFrequencies().empty())
    enableAction = true;
  // check if there are other spectra
  if (!m_molecule->spectraTypes().empty())
    enableAction = true;

  foreach (auto action, m_actions)
    action->setEnabled(enableAction);

  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));

  if (enableAction && m_dialog != nullptr) {
    gatherSpectra();
  }
}

void Spectra::moleculeChanged(unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  bool enableAction = false;
  // check to see if it has IR or Raman data
  if (!m_molecule->vibrationFrequencies().empty())
    enableAction = true;
  // check if there are other spectra
  if (!m_molecule->spectraTypes().empty())
    enableAction = true;

  foreach (auto action, m_actions)
    action->setEnabled(enableAction);

  if (enableAction && m_dialog != nullptr) {
    gatherSpectra();
  }
}

void Spectra::openDialog()
{
  if (m_molecule == nullptr)
    return;

  if (m_dialog == nullptr) {
    m_dialog = new SpectraDialog(qobject_cast<QWidget*>(this->parent()));
  }

  gatherSpectra();
  // update the elements
  auto elements = m_molecule->atomicNumbers();
  std::vector<unsigned char> atomicNumbers(elements.begin(), elements.end());
  m_dialog->setElements(atomicNumbers);
  m_dialog->show();
}

void Spectra::gatherSpectra()
{
  if (m_molecule == nullptr || m_dialog == nullptr)
    return;

  std::map<std::string, MatrixX> spectra;
  // copy any spectra from the molecule
  for (const auto& type : m_molecule->spectraTypes()) {
    spectra[type] = m_molecule->spectra(type);
  }

  // check to see if it has IR or Raman data
  if (!m_molecule->vibrationFrequencies().empty()) {
    const unsigned int n = m_molecule->vibrationFrequencies().size();

    MatrixX ir(n, 2);
    // check max intensity
    for (unsigned int i = 0; i < n; ++i) {
      ir(i, 0) = m_molecule->vibrationFrequencies()[i];
      ir(i, 1) = m_molecule->vibrationIRIntensities()[i];
    }

    spectra["IR"] = ir;

    if (m_molecule->vibrationRamanIntensities().size() ==
        m_molecule->vibrationFrequencies().size()) {
      MatrixX raman(n, 2);
      for (unsigned int i = 0; i < n; ++i) {
        raman(i, 0) = m_molecule->vibrationFrequencies()[i];
        raman(i, 1) = m_molecule->vibrationRamanIntensities()[i];
      }
      spectra["Raman"] = raman;
    }
  }

  m_dialog->setSpectra(spectra);
}

} // namespace Avogadro::QtPlugins
