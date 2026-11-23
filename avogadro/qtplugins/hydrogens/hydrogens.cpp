/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "hydrogens.h"

#include <avogadro/qtgui/commandregistry.h>
#include <avogadro/qtgui/hydrogentools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtGui/QKeySequence>
#include <QAction>

#include <QtCore/QStringList>

#include <functional>
#include <utility>
#include <vector>

namespace Avogadro::QtPlugins {

using HydrogenCounts = QtGui::HydrogenTools::HydrogenCounts;

namespace {

/** Emit only the changes that happened; nothing if no atoms changed. */
void emitHydrogenChanges(QtGui::Molecule& molecule,
                         const HydrogenCounts& counts)
{
  if (counts.added == 0 && counts.removed == 0)
    return;

  QtGui::Molecule::MoleculeChanges changes =
    QtGui::Molecule::Atoms | QtGui::Molecule::Bonds;
  if (counts.added > 0)
    changes |= QtGui::Molecule::Added;
  if (counts.removed > 0)
    changes |= QtGui::Molecule::Removed;
  molecule.emitChanged(changes);
}

/** The command result: { "added": n, "removed": m }. */
QVariantMap countsResult(const HydrogenCounts& counts)
{
  QVariantMap result;
  result[QStringLiteral("added")] = static_cast<qlonglong>(counts.added);
  result[QStringLiteral("removed")] = static_cast<qlonglong>(counts.removed);
  return result;
}

} // namespace

Hydrogens::Hydrogens(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_molecule(nullptr)
{
  auto* action = new QAction(tr("&Adjust Hydrogens"), this);
  action->setShortcut(QKeySequence("Ctrl+Alt+H"));
  action->setProperty("menu priority", 760);
  connect(action, SIGNAL(triggered()), SLOT(adjustHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Add Hydrogens"), this);
  action->setProperty("menu priority", 750);
  connect(action, SIGNAL(triggered()), SLOT(addHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("Remove E&xtra Hydrogens"), this);
  action->setProperty("menu priority", 740);
  connect(action, SIGNAL(triggered()), SLOT(removeHydrogens()));
  m_actions.append(action);

  action = new QAction(tr("&Remove All Hydrogens"), this);
  action->setProperty("menu priority", 730);
  connect(action, SIGNAL(triggered()), SLOT(removeAllHydrogens()));
  m_actions.append(action);

  registerHydrogensCommands();
}

Hydrogens::~Hydrogens() {}

QString Hydrogens::description() const
{
  return tr("Add/remove hydrogens from the current molecule.");
}

QList<QAction*> Hydrogens::actions() const
{
  return m_actions;
}

QStringList Hydrogens::menuPath(QAction*) const
{
  return QStringList() << tr("&Build") << tr("&Hydrogens");
}

void Hydrogens::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Hydrogens::adjustHydrogens()
{
  applyAdjustment(QtGui::HydrogenTools::AddAndRemove);
}

void Hydrogens::addHydrogens()
{
  applyAdjustment(QtGui::HydrogenTools::Add);
}

void Hydrogens::removeHydrogens()
{
  applyAdjustment(QtGui::HydrogenTools::Remove);
}

void Hydrogens::removeAllHydrogens()
{
  applyRemoveAll();
}

HydrogenCounts Hydrogens::applyAdjustment(
  QtGui::HydrogenTools::Adjustment adjustment)
{
  HydrogenCounts counts;
  if (m_molecule == nullptr)
    return counts;

  auto* rw = m_molecule->undoMolecule();

  // Check if any atom needs an adjustment before opening an undo macro.
  bool needed = false;
  const size_t numAtoms = rw->atomCount();
  for (size_t i = 0; i < numAtoms; ++i) {
    int diff = QtGui::HydrogenTools::valencyAdjustment(rw->atom(i));
    if (adjustment != QtGui::HydrogenTools::Remove && diff > 0) {
      needed = true;
      break;
    }
    if (adjustment != QtGui::HydrogenTools::Add && diff < 0) {
      std::vector<size_t> indices;
      if (QtGui::HydrogenTools::extraHydrogenIndices(rw->atom(i), -diff,
                                                     indices) > 0) {
        needed = true;
        break;
      }
    }
  }

  if (!needed)
    return counts;

  QString undoText;
  switch (adjustment) {
    case QtGui::HydrogenTools::Add:
      undoText = tr("Add Hydrogens");
      break;
    case QtGui::HydrogenTools::Remove:
      undoText = tr("Remove Hydrogens");
      break;
    case QtGui::HydrogenTools::AddAndRemove:
      undoText = tr("Adjust Hydrogens");
      break;
  }

  rw->beginMergeMode(undoText);
  counts = QtGui::HydrogenTools::adjustHydrogens(*rw, adjustment);
  rw->endMergeMode();

  emitHydrogenChanges(*m_molecule, counts);
  return counts;
}

HydrogenCounts Hydrogens::applyRemoveAll()
{
  HydrogenCounts counts;
  if (m_molecule == nullptr)
    return counts;

  auto* rw = m_molecule->undoMolecule();

  // Check if there are any hydrogens to remove before opening an undo macro.
  bool hasH = false;
  const size_t numAtoms = rw->atomCount();
  for (size_t i = 0; i < numAtoms; ++i) {
    if (rw->atomicNumber(i) == 1) {
      hasH = true;
      break;
    }
  }

  if (!hasH)
    return counts;

  rw->beginMergeMode(tr("Remove All Hydrogens"));
  counts.removed = QtGui::HydrogenTools::removeAllHydrogens(*rw);
  rw->endMergeMode();

  emitHydrogenChanges(*m_molecule, counts);
  return counts;
}

void Hydrogens::registerHydrogensCommands()
{
  // All four commands take no options and report the same result.
  auto addCommand = [this](const QString& name, const QString& description,
                           std::function<HydrogenCounts()> run) {
    QtGui::CommandSpec spec;
    spec.name = name;
    spec.description = description;
    spec.needsMolecule = true;
    spec.handler = [this,
                    run = std::move(run)](const QtGui::CommandArguments&) {
      emit commandFinished(QString(), countsResult(run()));
    };
    commandRegistry().add(std::move(spec));
  };

  addCommand(
    "addHydrogens",
    tr("Add any missing hydrogen atoms on atoms that have incomplete octets."),
    [this] { return applyAdjustment(QtGui::HydrogenTools::Add); });
  addCommand(
    "removeHydrogens",
    tr("Remove any extra hydrogen atoms on atoms with overfull octets."),
    [this] { return applyAdjustment(QtGui::HydrogenTools::Remove); });
  addCommand(
    "adjustHydrogens",
    tr("Add any missing hydrogen atoms, and remove any extra hydrogen atoms on "
       "any atoms that violate the octet rule."),
    [this] { return applyAdjustment(QtGui::HydrogenTools::AddAndRemove); });
  addCommand("removeAllHydrogens",
             tr("Remove all hydrogen atoms in the molecule."),
             [this] { return applyRemoveAll(); });
}

bool Hydrogens::handleCommand(const QString& command,
                              const QVariantMap& options)
{
  return commandRegistry().handle(command, options, m_molecule);
}

} // namespace Avogadro::QtPlugins
