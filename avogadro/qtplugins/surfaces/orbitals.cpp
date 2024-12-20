/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orbitals.h"
#include "orbitalwidget.h"

#include <avogadro/core/array.h>
#include <avogadro/core/basisset.h>
#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/variant.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QTimer>
#include <QtWidgets/QFileDialog>

namespace Avogadro::QtPlugins {

Orbitals::Orbitals(QObject* p)
  : ExtensionPlugin(p), m_molecule(nullptr), m_dialog(nullptr),
    m_action(new QAction(this))
{
  m_action->setEnabled(false);
  m_action->setText(tr("Molecular Orbitals…"));
  connect(m_action, SIGNAL(triggered()), SLOT(openDialog()));
}

Orbitals::~Orbitals() {}

QList<QAction*> Orbitals::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList Orbitals::menuPath(QAction*) const
{
  QStringList path;
  path << tr("&Analysis");
  return path;
}

void Orbitals::setMolecule(QtGui::Molecule* mol)
{
  if (mol == nullptr)
    return;

  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  m_molecule = mol;
  // check if it has basis set data
  bool hasOrbitals = (m_molecule->basisSet() != nullptr);

  if (hasOrbitals)
    m_action->setEnabled(true);
  else {
    m_action->setEnabled(false);
    if (m_dialog)
      m_dialog->hide();
  }

  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));

  // Stuff we manage that will not be valid any longer
  m_queue.clear();
  // m_currentRunningCalculation = -1;

  if (m_basis) {
    delete m_basis;
    m_basis = nullptr;
  }

  loadBasis();

  if (!m_basis || m_basis->electronCount() == 0)
    return; // no electrons, no orbitals

  loadOrbitals();
  precalculateOrbitals();
}

void Orbitals::loadBasis()
{
  // TODO
}

void Orbitals::loadOrbitals()
{
  if (m_basis == nullptr || m_molecule == nullptr)
    return;

  // Send MO data to table
  // TODO: Alpha / Beta orbitals
  QList<Orbital> list;
  unsigned int homo = m_basis->homo();
  unsigned int lumo = m_basis->lumo();
  unsigned int count = homo - 1;
  bool leqHOMO = true; // orbital <= homo

  // energies and symmetries
  // TODO: handle both alpha and beta (separate columns?)
  QList<QVariant> alphaEnergies;
  auto* gaussianBasis = dynamic_cast<Core::GaussianSet*>(m_basis);
  if (gaussianBasis != nullptr) {
    auto moEnergies = gaussianBasis->moEnergy();
    alphaEnergies.reserve(moEnergies.size());
    for (double energy : moEnergies) {
      alphaEnergies.push_back(energy);
    }
  }

  // not sure if any import supports symmetry labels yet
  const auto labels = m_basis->symmetryLabels();
  QStringList alphaSymmetries;
  alphaSymmetries.reserve(labels.size());
  for (const std::string label : labels) {
    alphaSymmetries.push_back(QString::fromStdString(label));
  }

  for (int i = 0; i < m_basis->molecularOrbitalCount(); i++) {
    QString num = "";
    if (i + 1 != homo && i + 1 != lumo) {
      num = (leqHOMO) ? "-" : "+";
      num += QString::number(count);
    }

    QString desc = QString("%1")
                     // (HOMO|LUMO)(+|-)[0-9]+
                     .arg((leqHOMO) ? tr("HOMO", "Highest Occupied MO") + num
                                    : tr("LUMO", "Lowest Unoccupied MO") + num);
    qDebug() << desc;

    Orbital orb;
    // Get the energy from the molecule property list, if available
    if (alphaEnergies.size() > i)
      orb.energy = alphaEnergies[i].toDouble();
    else
      orb.energy = 0.0;
    // symmetries (if available)
    if (alphaSymmetries.size() > i)
      orb.symmetry = alphaSymmetries[i];
    orb.index = i;
    orb.description = desc;
    orb.queueEntry = 0;
    orb.min = 0;
    orb.max = 0;
    orb.current = 0;

    list.append(orb);
    if (i + 1 < homo)
      count--;
    else if (i + 1 == homo)
      leqHOMO = false;
    else if (i + 1 >= lumo)
      count++;
  }
  m_dialog->fillTable(list);
}

void Orbitals::moleculeChanged(unsigned int changes)
{
  if (m_molecule == nullptr)
    return;

  bool isEnabled = m_action->isEnabled();
  bool hasOrbitals = (m_molecule->basisSet() != nullptr);

  if (isEnabled != hasOrbitals) {
    m_action->setEnabled(hasOrbitals);
    if (hasOrbitals)
      openDialog();
  }
}

void Orbitals::openDialog()
{
  if (!m_dialog) {
    m_dialog = new OrbitalWidget(qobject_cast<QWidget*>(parent()));
  }

  m_dialog->show();
}

void Orbitals::calculateOrbitalFromWidget(unsigned int orbital,
                                          double resolution)
{
  // TODO
}

void Orbitals::precalculateOrbitals()
{
  // TODO
}

void Orbitals::addCalculationToQueue(unsigned int orbital, double resolution,
                                     double isoval, unsigned int priority)
{
  // todo
}

void Orbitals::checkQueue()
{
  // TODO
}

void Orbitals::startCalculation(unsigned int queueIndex)
{
  // TODO
}

void Orbitals::calculateCube()
{
  // TODO
}
void Orbitals::calculateCubeDone()
{
  // TODO
}
void Orbitals::calculatePosMesh()
{
  // TODO
}
void Orbitals::calculatePosMeshDone()
{
  // TODO
}
void Orbitals::calculateNegMesh()
{
  // TODO
}
void Orbitals::calculateNegMeshDone()
{
  // TODO
}
void Orbitals::calculationComplete()
{
  // TODO
}

void Orbitals::renderOrbital(unsigned int orbital)
{
  // TODO
}

void Orbitals::updateProgress(int current)
{
  // TODO
}

} // namespace Avogadro::QtPlugins
