/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "bonding.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QAction>
#include <QDialog>
#include <QSettings>

#include <cmath>
#include <set>
#include <utility>
#include <vector>

#include "ui_bondingdialog.h"

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::Elements;

using NeighborListType = Avogadro::Core::Array<Avogadro::Core::Bond>;

Bonding::Bonding(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_),
    m_action(new QAction(tr("Bond Atoms"), this)),
    m_orderAction(new QAction(tr("Perceive Bond Orders"), this)),
    m_clearAction(new QAction(tr("Remove Bonds"), this)),
    m_configAction(new QAction(tr("Configure Bonding…"), this)),
    m_createBondsAction(new QAction(tr("Bond Selected Atoms"), this)),
    m_dialog(nullptr), m_ui(nullptr)
{
  QSettings settings;
  m_tolerance = settings.value("bonding/tolerance", 0.45).toDouble();
  m_minDistance = settings.value("bonding/minDistance", 0.32).toDouble();

  m_action->setShortcut(QKeySequence("Ctrl+B"));
  m_action->setProperty("menu priority", 750);
  m_createBondsAction->setProperty("menu priority", 740);
  m_orderAction->setProperty("menu priority", 735);
  m_clearAction->setShortcut(QKeySequence("Ctrl+Shift+B"));
  m_clearAction->setProperty("menu priority", 720);

  connect(m_action, &QAction::triggered, this, &Bonding::bond);
  connect(m_createBondsAction, &QAction::triggered, this, &Bonding::createBond);
  connect(m_orderAction, &QAction::triggered, this, &Bonding::bondOrders);
  connect(m_clearAction, &QAction::triggered, this, &Bonding::clearBonds);
  connect(m_configAction, &QAction::triggered, this, &Bonding::configure);
}

QList<QAction*> Bonding::actions() const
{
  QList<QAction*> result;
  return result << m_action << m_createBondsAction << m_orderAction
                << m_clearAction << m_configAction;
}

QStringList Bonding::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("Bond");
}

void Bonding::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Bonding::registerCommands()
{
  emit registerCommand("removeBonds",
                       tr("Remove bonds from all or selected atoms."));
  emit registerCommand("createBonds",
                       tr("Create bonds between all or selected atoms."));
  emit registerCommand("addBondOrders", tr("Perceive bond orders."));
}

bool Bonding::handleCommand(const QString& command,
                            [[maybe_unused]] const QVariantMap& options)
{
  if (m_molecule == nullptr)
    return false; // No molecule to handle the command.

  if (command == "removeBonds") {
    clearBonds();
    return true;
  } else if (command == "createBonds") {
    bond();
    return true;
  } else if (command == "addBondOrders") {
    bondOrders();
    return true;
  }
  return false;
}

void Bonding::configure()
{
  if (!m_ui) {
    m_dialog = new QDialog(qobject_cast<QWidget*>(parent()));
    m_ui = new Ui::BondingDialog;
    m_ui->setupUi(m_dialog);

    m_ui->toleranceSpinBox->setValue(m_tolerance);
    m_ui->minimumSpinBox->setValue(m_minDistance);

    connect(m_ui->buttonBox, &QDialogButtonBox::accepted, this,
            &Bonding::setValues);
    connect(m_ui->buttonBox, &QDialogButtonBox::rejected, m_dialog,
            &QDialog::close);
  }

  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void Bonding::setValues()
{
  if (m_dialog == nullptr || m_ui == nullptr)
    return;
  m_dialog->close();

  m_tolerance = m_ui->toleranceSpinBox->value();
  m_minDistance = m_ui->minimumSpinBox->value();

  QSettings settings;
  settings.setValue("bonding/tolerance", m_tolerance);
  settings.setValue("bonding/minDistance", m_minDistance);
}

void Bonding::createBond()
{
  // Create bond between selected atoms no matter the distance
  if (!m_molecule)
    return;

  if (m_molecule->isSelectionEmpty())
    return;

  // Only new bonds: adding a bond to an already-bonded pair would reset its
  // order (e.g. a perceived double bond) to 1.
  std::vector<std::pair<Index, Index>> newBonds;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!m_molecule->atomSelected(i))
      continue;

    for (Index j = i + 1; j < m_molecule->atomCount(); ++j) {
      if (!m_molecule->atomSelected(j))
        continue;

      if (!m_molecule->bond(i, j).isValid())
        newBonds.emplace_back(i, j);
    }
  }

  addBonds(newBonds, tr("Bond Selected Atoms"));
}

void Bonding::addBonds(const std::vector<std::pair<Index, Index>>& newBonds,
                       const QString& undoText)
{
  // No change, no undo entry
  if (newBonds.empty())
    return;

  QtGui::RWMolecule* rw = m_molecule->undoMolecule();
  rw->beginMergeMode(undoText);
  for (const auto& pair : newBonds)
    rw->addBond(pair.first, pair.second, 1);
  rw->endMergeMode();

  // The undo commands do not signal bond changes themselves
  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

void Bonding::bond()
{
  // Yes, this is largely reproduced from Core::Molecule::perceiveBondsSimple
  //  .. but that class doesn't know about selections
  if (!m_molecule)
    return;

  // Check for 3D coordinates, can't do bond perception without this.
  if (m_molecule->atomPositions3d().size() != m_molecule->atomCount())
    return;

  // cache atomic radii
  std::vector<double> radii(m_molecule->atomCount());
  for (size_t i = 0; i < radii.size(); i++) {
    radii[i] = Elements::radiusCovalent(m_molecule->atomicNumbers()[i]);
    if (radii[i] <= 0.0)
      radii[i] = 0.0;
  }

  bool emptySelection = m_molecule->isSelectionEmpty();
  double minSq = m_minDistance * m_minDistance;
  std::vector<std::pair<Index, Index>> newBonds;

  // Main bond perception loop based on a simple distance metric.
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!emptySelection && !m_molecule->atomSelected(i))
      continue;

    Vector3 ipos = m_molecule->atomPositions3d()[i];
    for (Index j = i + 1; j < m_molecule->atomCount(); ++j) {
      if (!emptySelection && !m_molecule->atomSelected(j))
        continue;

      double cutoff = radii[i] + radii[j] + m_tolerance;
      Vector3 jpos = m_molecule->atomPositions3d()[j];
      Vector3 diff = jpos - ipos;

      if (std::fabs(diff[0]) > cutoff || std::fabs(diff[1]) > cutoff ||
          std::fabs(diff[2]) > cutoff ||
          (m_molecule->atomicNumbers()[i] == 1 &&
           m_molecule->atomicNumbers()[j] == 1)) {
        continue;
      }

      // check radius and add bond if needed, leaving existing bonds (and
      // their orders) alone
      double cutoffSq = cutoff * cutoff;
      double diffsq = diff.squaredNorm();
      if (diffsq < cutoffSq && diffsq > minSq &&
          !m_molecule->bond(i, j).isValid())
        newBonds.emplace_back(i, j);
    }
  }

  addBonds(newBonds, tr("Bond Atoms"));
}

void Bonding::bondOrders()
{
  if (!m_molecule)
    return;

  // RWMolecule can't perceive bond orders, so do it on a copy and apply the
  // result as a single undoable change.
  Core::Molecule copy = static_cast<const Core::Molecule&>(*m_molecule);
  copy.perceiveBondOrders();

  // Perception only changes orders; refuse anything else
  if (copy.bondCount() != m_molecule->bondCount() ||
      copy.bondOrders() == m_molecule->bondOrders())
    return;

  QtGui::RWMolecule* rw = m_molecule->undoMolecule();
  rw->beginMergeMode(tr("Perceive Bond Orders"));
  rw->setBondOrders(copy.bondOrders());
  rw->endMergeMode();

  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

void Bonding::clearBonds()
{
  if (!m_molecule)
    return;

  // remove any bonds connected to the selected atoms, or all of them
  const bool all = m_molecule->isSelectionEmpty();

  // A bond between two selected atoms is listed once per atom, so collect
  // into a set. Removing a bond swaps the last bond into its slot, so remove
  // from the highest index down.
  std::set<Index> bondIndices;
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (!all && !m_molecule->atomSelected(i))
      continue;

    const NeighborListType bonds = m_molecule->bonds(i);
    for (const auto& bond : bonds)
      bondIndices.insert(bond.index());
  }

  // No change, no undo entry
  if (bondIndices.empty())
    return;

  QtGui::RWMolecule* rw = m_molecule->undoMolecule();
  rw->beginMergeMode(tr("Remove Bonds"));
  for (auto it = bondIndices.rbegin(), itEnd = bondIndices.rend(); it != itEnd;
       ++it) {
    rw->removeBond(*it);
  }
  rw->endMergeMode();

  m_molecule->emitChanged(QtGui::Molecule::Bonds);
}

} // namespace Avogadro::QtPlugins
