/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsextension.h"
#include "constraintsdialog.h"
#include "constraintsmodel.h"

#include <avogadro/core/constraint.h>
#include <avogadro/qtgui/commandregistry.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QMetaType>
#include <QtCore/QVariant>

#include <algorithm>
#include <array>
#include <cmath>
#include <string>
#include <iostream>

namespace Avogadro {
namespace QtPlugins {

namespace {

QString constraintTypeName(Core::Constraint::Type type)
{
  switch (type) {
    case Core::Constraint::DistanceConstraint:
      return QStringLiteral("distance");
    case Core::Constraint::AngleConstraint:
      return QStringLiteral("angle");
    case Core::Constraint::TorsionConstraint:
      return QStringLiteral("torsion");
    default:
      // Out-of-plane constraints are not created by this extension, but one
      // could exist already (e.g. read from a file); report it rather than
      // crashing or silently dropping it.
      return QStringLiteral("unknown");
  }
}

/// The atoms a constraint names, in the order listConstraints() documents:
/// only as many as its type actually uses. A type this extension does not
/// create (out-of-plane, or anything else matches() would not recognize)
/// lists whichever of its four indices are actually set.
QVariantList constraintAtomsList(const Core::Constraint& constraint)
{
  QVariantList atoms;
  switch (constraint.type()) {
    case Core::Constraint::DistanceConstraint:
      atoms << static_cast<qint64>(constraint.aIndex())
            << static_cast<qint64>(constraint.bIndex());
      break;
    case Core::Constraint::AngleConstraint:
      atoms << static_cast<qint64>(constraint.aIndex())
            << static_cast<qint64>(constraint.bIndex())
            << static_cast<qint64>(constraint.cIndex());
      break;
    case Core::Constraint::TorsionConstraint:
      atoms << static_cast<qint64>(constraint.aIndex())
            << static_cast<qint64>(constraint.bIndex())
            << static_cast<qint64>(constraint.cIndex())
            << static_cast<qint64>(constraint.dIndex());
      break;
    default:
      for (Index idx : { constraint.aIndex(), constraint.bIndex(),
                         constraint.cIndex(), constraint.dIndex() }) {
        if (idx != MaxIndex)
          atoms << static_cast<qint64>(idx);
      }
      break;
  }
  return atoms;
}

} // namespace

ConstraintsExtension::ConstraintsExtension(QObject* p) : ExtensionPlugin(p)
{
  QAction* action = new QAction(this);
  action->setEnabled(true);
  action->setText(tr("Constraints…"));
  connect(action, SIGNAL(triggered()), SLOT(openDialog()));
  m_actions.push_back(action);

  registerConstraintCommands();
}

ConstraintsExtension::~ConstraintsExtension()
{
  if (m_dialog)
    m_dialog->deleteLater();
}

QList<QAction*> ConstraintsExtension::actions() const
{
  return m_actions;
}

QStringList ConstraintsExtension::menuPath(QAction*) const
{
  return QStringList() << tr("&Extensions") << tr("&Calculate");
}

void ConstraintsExtension::openDialog()
{
  if (m_dialog == nullptr) {
    m_dialog = new ConstraintsDialog(qobject_cast<QWidget*>(parent()));
  }

  // update the constraints before we show the dialog
  if (m_molecule != nullptr)
    m_dialog->setMolecule(m_molecule);

  m_dialog->updateConstraints();

  m_dialog->show();
  m_dialog->raise();
  m_dialog->activateWindow();
}

void ConstraintsExtension::setMolecule(QtGui::Molecule* mol)
{
  if (mol != m_molecule) {
    m_molecule = mol;
  }

  if (m_dialog != nullptr)
    m_dialog->setMolecule(mol);
}

void ConstraintsExtension::registerConstraintCommands()
{
  using QtGui::CommandArgumentSpec;

  QtGui::CommandSpec list;
  list.name = "listConstraints";
  list.description =
    tr("List the geometry constraints on the current molecule. No options. "
       "Returns {\"constraints\": [{\"type\": \"distance\"|\"angle\"|"
       "\"torsion\", \"atoms\": [i, j, (k, (l))], \"value\": v}, …]}, "
       "with zero-based atom indices and value in Å for a distance or "
       "degrees for an angle or torsion.");
  list.handler = [this](const QtGui::CommandArguments&) {
    QVariantList entries;
    for (const auto& constraint : m_molecule->constraints()) {
      QVariantMap entry;
      entry[QStringLiteral("type")] = constraintTypeName(constraint.type());
      entry[QStringLiteral("atoms")] = constraintAtomsList(constraint);
      entry[QStringLiteral("value")] = constraint.value();
      entries << entry;
    }
    QVariantMap result;
    result[QStringLiteral("constraints")] = entries;
    emit commandFinished(QString(), result);
  };
  commandRegistry().add(std::move(list));

  // The atom count (2, 3 or 4) decides the constraint type.
  const CommandArgumentSpec atoms =
    CommandArgumentSpec::atomIndices(
      "atoms", tr("Zero-based atom indices: 2 for a distance, 3 for an angle "
                  "or 4 for a torsion."))
      .withRequired()
      .withCount(2, 4);

  QtGui::CommandSpec add;
  add.name = "addConstraint";
  add.description =
    tr("Add or update a geometry constraint, given as zero-based atom "
       "indices: {\"atoms\": [i, j]} for a distance, {\"atoms\": [i, j, "
       "k]} for an angle, or {\"atoms\": [i, j, k, l]} for a torsion, plus "
       "an optional {\"value\": …} in Å for a distance or degrees "
       "for an angle or torsion. If \"value\" is omitted, the current "
       "geometry of those atoms is measured and used. If a constraint "
       "already exists on the same atoms (in either order), its value is "
       "updated instead of adding a duplicate. Returns {\"type\": …, "
       "\"atoms\": […], \"value\": …, \"updated\": bool}.");
  // The valid range depends on the constraint type, and on a measured
  // default, so it is checked in addConstraint().
  add.arguments = { atoms,
                    CommandArgumentSpec::real(
                      "value", tr("Target in Å for a distance or degrees for "
                                  "an angle or torsion. Defaults to the "
                                  "current geometry.")) };
  add.handler = [this](const QtGui::CommandArguments& args) {
    addConstraint(args);
  };
  commandRegistry().add(std::move(add));

  QtGui::CommandSpec remove;
  remove.name = "removeConstraint";
  remove.description =
    tr("Remove the constraint on the given zero-based atom indices (in "
       "either order): {\"atoms\": [i, j, (k, (l))]}. Returns "
       "{\"removed\": count}.");
  remove.arguments = { atoms };
  remove.handler = [this](const QtGui::CommandArguments& args) {
    removeConstraint(args);
  };
  commandRegistry().add(std::move(remove));

  QtGui::CommandSpec clear;
  clear.name = "clearConstraints";
  clear.description =
    tr("Remove all geometry constraints from the current molecule. No "
       "options. Returns {\"removed\": count}.");
  clear.handler = [this](const QtGui::CommandArguments&) {
    const auto removed = static_cast<qint64>(m_molecule->constraints().size());
    m_molecule->clearConstraints();
    m_molecule->emitChanged(QtGui::Molecule::Constraints);
    if (m_dialog)
      m_dialog->updateConstraints();

    QVariantMap result;
    result[QStringLiteral("removed")] = removed;
    emit commandFinished(QString(), result);
  };
  commandRegistry().add(std::move(clear));
}

bool ConstraintsExtension::handleCommand(const QString& command,
                                         const QVariantMap& options)
{
  return commandRegistry().handle(command, options, m_molecule);
}

namespace {
/// The atoms of a validated 2 to 4 index list, padded with MaxIndex.
std::array<Index, 4> paddedAtoms(const std::vector<Index>& atoms)
{
  std::array<Index, 4> result = { MaxIndex, MaxIndex, MaxIndex, MaxIndex };
  for (size_t i = 0; i < atoms.size() && i < 4; ++i)
    result[i] = atoms[i];
  return result;
}
} // namespace

void ConstraintsExtension::removeConstraint(const QtGui::CommandArguments& args)
{
  const std::vector<Index> atomIndices = args.atoms(QStringLiteral("atoms"));
  const auto padded = paddedAtoms(atomIndices);
  const Index a = padded[0];
  const Index b = padded[1];
  const Index c = padded[2];
  const Index d = padded[3];

  auto& constraints = m_molecule->constraints();
  const auto before = constraints.size();
  constraints.erase(
    std::remove_if(constraints.begin(), constraints.end(),
                   [a, b, c, d](const Core::Constraint& constraint) {
                     return constraint.matches(a, b, c, d);
                   }),
    constraints.end());
  const auto removed = before - constraints.size();

  if (removed == 0) {
    emit commandFailed(tr("No constraint matches these atoms."));
    return;
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
  if (m_dialog)
    m_dialog->updateConstraints();

  QVariantMap result;
  result[QStringLiteral("removed")] = static_cast<qint64>(removed);
  emit commandFinished(QString(), result);
}

void ConstraintsExtension::addConstraint(const QtGui::CommandArguments& args)
{
  const std::vector<Index> atomIndices = args.atoms(QStringLiteral("atoms"));
  const auto padded = paddedAtoms(atomIndices);
  const Index a = padded[0];
  const Index b = padded[1];
  const Index c = padded[2];
  const Index d = padded[3];

  // The atom count decides the type (2 = distance, 3 = angle, 4 = torsion);
  // the atoms spec already restricted it to one of those three.
  Core::Constraint::Type type;
  switch (atomIndices.size()) {
    case 2:
      type = Core::Constraint::DistanceConstraint;
      break;
    case 3:
      type = Core::Constraint::AngleConstraint;
      break;
    default:
      type = Core::Constraint::TorsionConstraint;
      break;
  }

  double value = 0.0;
  if (args.has(QStringLiteral("value"))) {
    value = args.real(QStringLiteral("value"));
  } else {
    // Measure the current geometry with the constraint's own evaluate(),
    // the same code an optimizer or the measure tool would use, so the
    // default value and its sign convention always match what is actually
    // enforced.
    const Core::Constraint temp(a, b, c, d);
    if (!temp.evaluate(m_molecule->atomPositions3d(), value)) {
      emit commandFailed(
        tr("Could not measure the current geometry for these atoms."));
      return;
    }
  }

  // Match the dialog's spin box ranges. A zero distance would stack two
  // atoms on top of each other, and an angle outside 0-180 degrees lands on
  // the supplement, so the caller would get back a value it never asked
  // for. Torsions wrap, so any value is meaningful.
  if (type == Core::Constraint::DistanceConstraint && !(value > 0.0)) {
    emit commandFailed(tr("value must be a distance greater than 0 Å."));
    return;
  }
  if (type == Core::Constraint::AngleConstraint &&
      !(value >= 0.0 && value <= 180.0)) {
    emit commandFailed(tr("value must be an angle from 0 to 180 degrees."));
    return;
  }

  // If an existing constraint of the same type already matches these atoms
  // (in either order), update its value instead of adding a duplicate --
  // mirrors ConstraintsDialog::addConstraint().
  bool updated = false;
  for (auto& existing : m_molecule->constraints()) {
    if (existing.type() == type && existing.matches(a, b, c, d)) {
      existing.setValue(value);
      updated = true;
      break;
    }
  }
  if (!updated) {
    Core::Constraint newConstraint(a, b, c, d, value);
    newConstraint.setType(type);
    m_molecule->addConstraint(newConstraint);
  }

  m_molecule->emitChanged(QtGui::Molecule::Constraints);
  if (m_dialog)
    m_dialog->updateConstraints();

  QVariantList atomsResult;
  for (Index index : atomIndices)
    atomsResult.append(static_cast<qint64>(index));

  QVariantMap result;
  result[QStringLiteral("type")] = constraintTypeName(type);
  result[QStringLiteral("atoms")] = atomsResult;
  result[QStringLiteral("value")] = value;
  result[QStringLiteral("updated")] = updated;
  emit commandFinished(QString(), result);
}

} // namespace QtPlugins
} // namespace Avogadro
