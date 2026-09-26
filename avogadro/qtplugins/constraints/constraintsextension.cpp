/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "constraintsextension.h"
#include "constraintsdialog.h"
#include "constraintsmodel.h"

#include <avogadro/core/constraint.h>

#include <QAction>
#include <QDebug>
#include <QtCore/QMetaType>
#include <QtCore/QVariant>

#include <algorithm>
#include <cmath>
#include <string>
#include <iostream>

namespace Avogadro {
namespace QtPlugins {

namespace {

/// Whether @p value holds an actual JSON number, as opposed to some other
/// JSON type that QVariant would still convert on request -- a QString "3"
/// or a JSON boolean, say. Atom indices and values must be rejected rather
/// than silently coerced.
bool isNumericVariant(const QVariant& value)
{
  switch (value.typeId()) {
    case QMetaType::Double:
    case QMetaType::Float:
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
      return true;
    default:
      return false;
  }
}

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

void ConstraintsExtension::registerCommands()
{
  emit registerCommand(
    "listConstraints",
    tr("List the geometry constraints on the current molecule. No options. "
       "Returns {\"constraints\": [{\"type\": \"distance\"|\"angle\"|"
       "\"torsion\", \"atoms\": [i, j, (k, (l))], \"value\": v}, ...]}, "
       "with zero-based atom indices and value in Å for a distance or "
       "degrees for an angle or torsion."));
  emit registerCommand(
    "addConstraint",
    tr("Add or update a geometry constraint, given as zero-based atom "
       "indices: {\"atoms\": [i, j]} for a distance, {\"atoms\": [i, j, "
       "k]} for an angle, or {\"atoms\": [i, j, k, l]} for a torsion, plus "
       "an optional {\"value\": ...} in Å for a distance or degrees "
       "for an angle or torsion. If \"value\" is omitted, the current "
       "geometry of those atoms is measured and used. If a constraint "
       "already exists on the same atoms (in either order), its value is "
       "updated instead of adding a duplicate. Returns {\"type\": ..., "
       "\"atoms\": [...], \"value\": ..., \"updated\": bool}."));
  emit registerCommand(
    "removeConstraint",
    tr("Remove the constraint on the given zero-based atom indices (in "
       "either order): {\"atoms\": [i, j, (k, (l))]}. Returns "
       "{\"removed\": count}."));
  emit registerCommand(
    "clearConstraints",
    tr("Remove all geometry constraints from the current molecule. No "
       "options. Returns {\"removed\": count}."));
}

bool ConstraintsExtension::handleCommand(const QString& command,
                                         const QVariantMap& options)
{
  if (command != QLatin1String("listConstraints") &&
      command != QLatin1String("addConstraint") &&
      command != QLatin1String("removeConstraint") &&
      command != QLatin1String("clearConstraints")) {
    // Not one of ours.
    return false;
  }

  if (!m_molecule) {
    emit commandFailed(tr("There is no molecule to constrain."));
    return true;
  }

  if (command == QLatin1String("listConstraints")) {
    QVariantList list;
    for (const auto& constraint : m_molecule->constraints()) {
      QVariantMap entry;
      entry[QStringLiteral("type")] = constraintTypeName(constraint.type());
      entry[QStringLiteral("atoms")] = constraintAtomsList(constraint);
      entry[QStringLiteral("value")] = constraint.value();
      list << entry;
    }
    QVariantMap result;
    result[QStringLiteral("constraints")] = list;
    emit commandFinished(QString(), result);
    return true;
  }

  if (command == QLatin1String("clearConstraints")) {
    const auto removed = static_cast<qint64>(m_molecule->constraints().size());
    m_molecule->clearConstraints();
    m_molecule->emitChanged(QtGui::Molecule::Constraints);
    if (m_dialog)
      m_dialog->updateConstraints();

    QVariantMap result;
    result[QStringLiteral("removed")] = removed;
    emit commandFinished(QString(), result);
    return true;
  }

  // addConstraint and removeConstraint both take an "atoms" list.
  QVector<Index> atomIndices;
  QString error;
  if (!parseAtomIndices(options, atomIndices, error)) {
    emit commandFailed(error);
    return true;
  }

  const Index a = atomIndices[0];
  const Index b = atomIndices[1];
  const Index c = atomIndices.size() > 2 ? atomIndices[2] : MaxIndex;
  const Index d = atomIndices.size() > 3 ? atomIndices[3] : MaxIndex;

  if (command == QLatin1String("removeConstraint")) {
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
      return true;
    }

    m_molecule->emitChanged(QtGui::Molecule::Constraints);
    if (m_dialog)
      m_dialog->updateConstraints();

    QVariantMap result;
    result[QStringLiteral("removed")] = static_cast<qint64>(removed);
    emit commandFinished(QString(), result);
    return true;
  }

  // addConstraint: the atom count decides the type (2 = distance, 3 =
  // angle, 4 = torsion) -- parseAtomIndices() already restricted it to one
  // of those three.
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
  if (options.contains(QStringLiteral("value"))) {
    const QVariant valueVariant = options.value(QStringLiteral("value"));
    if (!isNumericVariant(valueVariant)) {
      switch (type) {
        case Core::Constraint::DistanceConstraint:
          emit commandFailed(tr("value must be a number: a distance in Å."));
          break;
        case Core::Constraint::AngleConstraint:
          emit commandFailed(
            tr("value must be a number: an angle in degrees."));
          break;
        default:
          emit commandFailed(
            tr("value must be a number: a dihedral angle in degrees."));
          break;
      }
      return true;
    }
    value = valueVariant.toDouble();
  } else {
    // Measure the current geometry with the constraint's own evaluate(),
    // the same code an optimizer or the measure tool would use, so the
    // default value and its sign convention always match what is actually
    // enforced.
    const Core::Constraint temp(a, b, c, d);
    if (!temp.evaluate(m_molecule->atomPositions3d(), value)) {
      emit commandFailed(
        tr("Could not measure the current geometry for these atoms."));
      return true;
    }
  }

  // Match the dialog's spin box ranges. A zero distance would stack two
  // atoms on top of each other, and an angle outside 0-180 degrees lands on
  // the supplement, so the caller would get back a value it never asked
  // for. Torsions wrap, so any value is meaningful.
  if (type == Core::Constraint::DistanceConstraint && !(value > 0.0)) {
    emit commandFailed(tr("value must be a distance greater than 0 Å."));
    return true;
  }
  if (type == Core::Constraint::AngleConstraint &&
      !(value >= 0.0 && value <= 180.0)) {
    emit commandFailed(tr("value must be an angle from 0 to 180 degrees."));
    return true;
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
  return true;
}

bool ConstraintsExtension::parseAtomIndices(const QVariantMap& options,
                                            QVector<Index>& indices,
                                            QString& error) const
{
  indices.clear();

  const QVariant atomsValue = options.value(QStringLiteral("atoms"));
  if (atomsValue.typeId() != QMetaType::QVariantList) {
    error = tr("atoms must be a list of 2 (distance), 3 (angle) or 4 "
               "(torsion) zero-based atom indices.");
    return false;
  }

  const QVariantList atomsList = atomsValue.toList();
  if (atomsList.size() < 2 || atomsList.size() > 4) {
    error = tr("atoms must list 2 (distance), 3 (angle) or 4 (torsion) atom "
               "indices.");
    return false;
  }

  const Index atomCount = m_molecule->atomCount();
  QVector<Index> parsed;
  parsed.reserve(atomsList.size());

  for (int i = 0; i < atomsList.size(); ++i) {
    if (!isNumericVariant(atomsList[i])) {
      error = tr("atom index #%1 in atoms must be a whole number.").arg(i + 1);
      return false;
    }

    const double raw = atomsList[i].toDouble();
    if (std::isnan(raw) || std::floor(raw) != raw) {
      error = tr("atom index #%1 in atoms must be a whole number.").arg(i + 1);
      return false;
    }
    if (raw < 0.0) {
      error = tr("atom index #%1 in atoms is negative; atom indices must "
                 "be zero or greater.")
                .arg(i + 1);
      return false;
    }
    // Comparing as doubles, before casting, keeps an absurdly large index
    // from overflowing Index rather than simply failing this check.
    if (!(raw < static_cast<double>(atomCount))) {
      // %n lets each language supply its own plural forms for "atoms".
      error = tr("atom index %1 is out of range (the molecule has %n "
                 "atom(s)).",
                 nullptr, static_cast<int>(atomCount))
                .arg(raw, 0, 'f', 0);
      return false;
    }

    const auto index = static_cast<Index>(raw);
    if (parsed.contains(index)) {
      error = tr("atom index %1 is repeated in atoms; each atom must be "
                 "different.")
                .arg(index);
      return false;
    }

    parsed.push_back(index);
  }

  indices = parsed;
  return true;
}

} // namespace QtPlugins
} // namespace Avogadro
