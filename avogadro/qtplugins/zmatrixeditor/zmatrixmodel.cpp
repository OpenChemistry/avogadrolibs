/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zmatrixmodel.h"

#include <avogadro/core/angletools.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/fragmenttools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QCoreApplication>

#include <algorithm>
#include <cmath>

namespace Avogadro::QtPlugins {

using QtGui::FragmentTools;
using QtGui::Molecule;

namespace {

// Distances are shown to a hundredth of a picometre and angles to a
// thousandth of a degree, which is finer than any method that produced them
// and coarse enough to stay readable.
const int distanceDecimals = 4;
const int angleDecimals = 3;

// Below this two atoms are on top of each other and no direction, angle or
// torsion between them means anything.
const Real coincidentTolerance = 1e-8;

// |sin| below which a row's angle counts as straight, mirroring the
// reference tolerance in internalcoordinates.cpp. About one degree. A row
// this close to straight describes nothing that can be edited, and is what
// a dummy atom is offered to fix.
const Real straightTolerance = 0.0175;

// The marker a constrained value carries, the same one the property tables
// put on a frozen coordinate.
const char* constrainedMarker = "🔒";

} // namespace

ZMatrixModel::ZMatrixModel(QObject* parent_) : QAbstractTableModel(parent_) {}

int ZMatrixModel::rowCount(const QModelIndex& parent_) const
{
  if (parent_.isValid())
    return 0;
  return static_cast<int>(m_coordinates.size());
}

int ZMatrixModel::columnCount(const QModelIndex& parent_) const
{
  if (parent_.isValid())
    return 0;
  return ColumnCount;
}

Index ZMatrixModel::gatingReference(const Core::InternalCoordinate& coordinate,
                                    int column)
{
  switch (column) {
    case AColumn:
    case DistanceColumn:
      return coordinate.a;
    case BColumn:
    case AngleColumn:
      return coordinate.b;
    case CColumn:
    case DihedralColumn:
      return coordinate.c;
    default:
      return MaxIndex; // the element column depends on no reference
  }
}

Index ZMatrixModel::atomForRow(int row) const
{
  if (row < 0 || row >= static_cast<int>(m_rowToAtom.size()))
    return MaxIndex;
  return m_rowToAtom[row];
}

int ZMatrixModel::rowForAtom(Index atom) const
{
  for (size_t row = 0; row < m_rowToAtom.size(); ++row) {
    if (m_rowToAtom[row] == atom)
      return static_cast<int>(row);
  }
  return -1;
}

QVariant ZMatrixModel::headerData(int section, Qt::Orientation orientation,
                                  int role) const
{
  if (role == Qt::DisplayRole && orientation == Qt::Horizontal) {
    switch (section) {
      case ElementColumn:
        return tr("Element");
      case AColumn:
      case BColumn:
      case CColumn:
        // The three reference columns are unlabelled on purpose: a header of
        // "a", "b", "c" reads as data in a table that is otherwise numbers.
        return QString();
      case DistanceColumn:
        return tr("Distance (Å)");
      case AngleColumn:
        return tr("Angle (°)");
      case DihedralColumn:
        return tr("Dihedral (°)");
      default:
        return QVariant();
    }
  }

  // The vertical header names the atom a row places, not the row's position,
  // so that it reads the same way as the reference columns do.
  if (role == Qt::DisplayRole && orientation == Qt::Vertical) {
    const Index atom = atomForRow(section);
    if (atom == MaxIndex)
      return QVariant();
    return QString::number(atom + 1);
  }

  return QVariant();
}

QVariant ZMatrixModel::data(const QModelIndex& index_, int role) const
{
  if (!index_.isValid() || m_molecule == nullptr)
    return QVariant();

  const int row = index_.row();
  if (row < 0 || row >= static_cast<int>(m_coordinates.size()))
    return QVariant();

  const Core::InternalCoordinate& coordinate = m_coordinates[row];
  const Index atom = m_rowToAtom[row];

  if (role == Qt::TextAlignmentRole) {
    return index_.column() == ElementColumn
             ? QVariant(Qt::AlignLeft | Qt::AlignVCenter)
             : QVariant(Qt::AlignRight | Qt::AlignVCenter);
  }

  // The lock a constrained value carries says nothing about what it is
  // constrained to, which is not always where the coordinate currently sits.
  if (role == Qt::ToolTipRole) {
    const Core::Constraint* constraint = constraintFor(row, index_.column());
    if (constraint == nullptr)
      return QVariant();
    return index_.column() == DistanceColumn
             ? tr("Constrained to %1 Å")
                 .arg(constraint->value(), 0, 'f', distanceDecimals)
             : tr("Constrained to %1°")
                 .arg(constraint->value(), 0, 'f', angleDecimals);
  }

  if (role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  // A row near the top of the matrix has fewer than three references, since
  // there are not yet three atoms to measure against. Those cells are empty
  // rather than zero: there is no value, as opposed to a value of nothing.
  if (index_.column() == ElementColumn)
    return QString(Core::Elements::symbol(m_molecule->atomicNumber(atom)));

  if (gatingReference(coordinate, index_.column()) == MaxIndex)
    return QString();

  Real value = 0.0;
  int decimals = angleDecimals;

  switch (index_.column()) {
    case AColumn:
      return QString::number(coordinate.a + 1);
    case BColumn:
      return QString::number(coordinate.b + 1);
    case CColumn:
      return QString::number(coordinate.c + 1);
    case DistanceColumn:
      value = coordinate.length;
      decimals = distanceDecimals;
      break;
    case AngleColumn:
      value = coordinate.angle;
      break;
    case DihedralColumn:
      value = coordinate.dihedral;
      break;
    default:
      return QVariant();
  }

  QString text = QString::number(value, 'f', decimals);

  // The marker is on the display only. An edit has to start from the number
  // by itself, or committing a cell the person never touched would fail to
  // parse and quietly throw the value away.
  if (role == Qt::DisplayRole && constraintFor(row, index_.column()) != nullptr)
    text += constrainedMarker;

  return text;
}

bool ZMatrixModel::coordinateAtoms(int row, int column,
                                   std::array<Index, 4>& atoms) const
{
  if (row < 0 || row >= static_cast<int>(m_coordinates.size()))
    return false;

  const Core::InternalCoordinate& coordinate = m_coordinates[row];
  const Index atom = m_rowToAtom[row];

  // A row near the top of the matrix has fewer than three references, so the
  // coordinate the column would show does not exist there. The references
  // are filled in order, so the last one a column needs is the only one to
  // check.
  switch (column) {
    case DistanceColumn:
      if (coordinate.a == MaxIndex)
        return false;
      atoms = { atom, coordinate.a, MaxIndex, MaxIndex };
      return true;
    case AngleColumn:
      if (coordinate.b == MaxIndex)
        return false;
      atoms = { atom, coordinate.a, coordinate.b, MaxIndex };
      return true;
    case DihedralColumn:
      if (coordinate.c == MaxIndex)
        return false;
      atoms = { atom, coordinate.a, coordinate.b, coordinate.c };
      return true;
    default:
      return false; // the element and reference columns are not coordinates
  }
}

bool ZMatrixModel::hasCoordinate(int row, int column) const
{
  std::array<Index, 4> atoms{};
  return coordinateAtoms(row, column, atoms);
}

const Core::Constraint* ZMatrixModel::constraintFor(int row, int column) const
{
  std::array<Index, 4> atoms{};
  if (m_molecule == nullptr || !coordinateAtoms(row, column, atoms))
    return nullptr;

  for (const Core::Constraint& constraint : m_molecule->constraints()) {
    if (constraint.matches(atoms[0], atoms[1], atoms[2], atoms[3]))
      return &constraint;
  }

  return nullptr;
}

bool ZMatrixModel::applyConstraint(int row, int column, bool constrained)
{
  std::array<Index, 4> atoms{};
  if (!coordinateAtoms(row, column, atoms))
    return false;

  // A coordinate carries at most one constraint, so setting one replaces
  // whatever was on it rather than stacking a second restraint alongside.
  auto& constraints = m_molecule->constraints();
  const size_t before = constraints.size();
  constraints.erase(
    std::remove_if(constraints.begin(), constraints.end(),
                   [&atoms](const Core::Constraint& constraint) {
                     return constraint.matches(atoms[0], atoms[1], atoms[2],
                                               atoms[3]);
                   }),
    constraints.end());

  if (!constrained)
    return constraints.size() != before;

  // The value is the one the table is showing, which refreshValues() keeps
  // level with the geometry, so constraining holds the coordinate where the
  // person can see it is.
  const Core::InternalCoordinate& coordinate = m_coordinates[row];
  Real value = coordinate.length;
  if (column == AngleColumn)
    value = coordinate.angle;
  else if (column == DihedralColumn)
    value = coordinate.dihedral;

  Core::Constraint constraint(atoms[0], atoms[1], atoms[2], atoms[3], value);
  m_molecule->addConstraint(constraint);
  return true;
}

bool ZMatrixModel::setConstrained(const QList<int>& rows, int column,
                                  bool constrained)
{
  if (m_molecule == nullptr)
    return false;

  bool changed = false;
  for (int row : rows)
    changed = applyConstraint(row, column, constrained) || changed;

  if (!changed)
    return false;

  // Coming back round through updateTable() is what repaints the locks, and
  // it also brings the constraint dialog and the property tables along.
  m_molecule->emitChanged(Molecule::Constraints);
  return true;
}

Qt::ItemFlags ZMatrixModel::flags(const QModelIndex& index_) const
{
  Qt::ItemFlags result = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
  if (!index_.isValid() || m_molecule == nullptr)
    return result;

  const int row = index_.row();
  if (row < 0 || row >= static_cast<int>(m_coordinates.size()))
    return result;

  const Core::InternalCoordinate& coordinate = m_coordinates[row];

  // A cell is editable only where the row actually has that reference.
  if (index_.column() == ElementColumn ||
      gatingReference(coordinate, index_.column()) != MaxIndex)
    return result | Qt::ItemIsEditable;

  return result;
}

QString ZMatrixModel::referenceError(int row, Index reference,
                                     Column column) const
{
  if (m_molecule == nullptr || reference >= m_molecule->atomCount())
    return tr("There is no atom %1.").arg(reference + 1);

  if (reference == m_rowToAtom[row])
    return tr("An atom cannot be measured against itself.");

  const Core::InternalCoordinate& coordinate = m_coordinates[row];
  if ((column != AColumn && reference == coordinate.a) ||
      (column != BColumn && reference == coordinate.b) ||
      (column != CColumn && reference == coordinate.c)) {
    return tr("Atom %1 is already used by this row.").arg(reference + 1);
  }

  // A row can only be measured against atoms that are already placed, which
  // is what makes the matrix a z-matrix.
  const int referenceRow = rowForAtom(reference);
  if (referenceRow < 0 || referenceRow >= row) {
    return tr("Atom %1 is placed after this one, so it cannot be measured "
              "against. Reorder the atoms first.")
      .arg(reference + 1);
  }

  return QString();
}

bool ZMatrixModel::setData(const QModelIndex& index_, const QVariant& value,
                           int role)
{
  if (!index_.isValid() || role != Qt::EditRole || m_molecule == nullptr)
    return false;

  const int row = index_.row();
  if (row < 0 || row >= static_cast<int>(m_coordinates.size()))
    return false;

  Core::InternalCoordinate& coordinate = m_coordinates[row];
  const Index atom = m_rowToAtom[row];
  auto* undoMolecule = m_molecule->undoMolecule();
  if (undoMolecule == nullptr)
    return false;

  switch (index_.column()) {
    case ElementColumn: {
      // Accept either a symbol or an atomic number, and Xx or 0 for the
      // dummy atoms a z-matrix uses to pin down linear fragments.
      bool ok = false;
      int atomicNumber = value.toInt(&ok);
      if (!ok) {
        atomicNumber = Core::Elements::atomicNumberFromSymbol(
          value.toString().trimmed().toStdString());
        if (atomicNumber == InvalidElement)
          return false;
      }
      if (atomicNumber < 0 || atomicNumber > 118)
        return false;
      undoMolecule->setAtomicNumber(atom,
                                    static_cast<unsigned char>(atomicNumber));
      m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
      return true;
    }

    case AColumn:
    case BColumn:
    case CColumn: {
      bool ok = false;
      const int entered = value.toInt(&ok);
      if (!ok || entered < 1)
        return false;
      const auto reference = static_cast<Index>(entered - 1);
      const auto column = static_cast<Column>(index_.column());
      const QString error = referenceError(row, reference, column);
      if (!error.isEmpty()) {
        emit referenceRejected(error);
        return false;
      }

      // Changing a reference does not move anything. The same geometry is
      // simply expressed against different atoms, so only the values are
      // recomputed.
      if (column == AColumn)
        coordinate.a = reference;
      else if (column == BColumn)
        coordinate.b = reference;
      else
        coordinate.c = reference;

      refreshValues();
      return true;
    }

    case DistanceColumn: {
      bool ok = false;
      const double length = value.toDouble(&ok);
      if (!ok || length <= 0.0)
        return false;
      if (!FragmentTools::setDistance(*undoMolecule, atom, coordinate.a,
                                      length))
        return false;
      break;
    }

    case AngleColumn: {
      bool ok = false;
      const double angle = value.toDouble(&ok);
      if (!ok)
        return false;
      if (!FragmentTools::setAngle(*undoMolecule, atom, coordinate.a,
                                   coordinate.b, angle))
        return false;
      break;
    }

    case DihedralColumn: {
      bool ok = false;
      const double dihedral = value.toDouble(&ok);
      if (!ok)
        return false;
      if (!FragmentTools::setTorsion(*undoMolecule, atom, coordinate.a,
                                     coordinate.b, coordinate.c, dihedral))
        return false;
      break;
    }

    default:
      return false;
  }

  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  return true;
}

void ZMatrixModel::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule == m_molecule)
    return;

  if (m_molecule != nullptr)
    m_molecule->disconnect(this);

  m_molecule = molecule;

  if (m_molecule != nullptr) {
    connect(m_molecule, SIGNAL(changed(unsigned int)), this,
            SLOT(updateTable(unsigned int)));
  }

  if (m_active) {
    rebuildStructure();
    return;
  }

  // Deferring the rebuild must not leave the previous molecule's rows behind,
  // since they index atoms that belong to a different molecule. Empty the
  // table now and fill it when the dock is next shown.
  beginResetModel();
  m_coordinates.clear();
  m_rowToAtom.clear();
  m_lastBondCount = 0;
  m_dirty = true;
  m_degenerate = false;
  endResetModel();
}

void ZMatrixModel::updateTable(unsigned int changes)
{
  Q_UNUSED(changes);

  // Every atom dragged and every optimisation step reaches here. Doing the
  // work for a dock nobody is looking at would cost an acos and an atan2 per
  // atom each time, so note it and catch up when the dock is shown.
  if (!m_active) {
    m_dirty = true;
    return;
  }

  if (m_molecule == nullptr) {
    rebuildStructure();
    return;
  }

  // Only a change in which atoms or bonds exist can invalidate the row order
  // or the references. Anything else has just moved atoms about, and the
  // references the person is working against are left as they are.
  if (m_molecule->atomCount() != m_rowToAtom.size() ||
      m_molecule->bondCount() != m_lastBondCount) {
    rebuildStructure();
    return;
  }

  refreshValues();
}

void ZMatrixModel::setActive(bool active)
{
  if (active == m_active)
    return;

  m_active = active;
  if (m_active && m_dirty)
    updateTable(0);
}

void ZMatrixModel::rebuildStructure()
{
  beginResetModel();

  m_coordinates.clear();
  m_rowToAtom.clear();

  if (m_molecule != nullptr) {
    m_coordinates = Core::cartesianToInternal(*m_molecule, m_rowToAtom);
    m_lastBondCount = m_molecule->bondCount();
  } else {
    m_lastBondCount = 0;
  }
  m_dirty = false;
  updateDegenerateRows();

  endResetModel();
}

void ZMatrixModel::refreshValues()
{
  if (m_molecule == nullptr || m_coordinates.empty())
    return;

  for (size_t row = 0; row < m_coordinates.size(); ++row) {
    Core::InternalCoordinate& coordinate = m_coordinates[row];
    const Index atom = m_rowToAtom[row];
    if (atom >= m_molecule->atomCount())
      continue;

    coordinate.length = 0.0;
    coordinate.angle = 0.0;
    coordinate.dihedral = 0.0;

    if (coordinate.a == MaxIndex)
      continue;

    const Vector3 position = m_molecule->atomPosition3d(atom);
    const Vector3 positionA = m_molecule->atomPosition3d(coordinate.a);
    coordinate.length = (position - positionA).norm();

    if (coordinate.b == MaxIndex)
      continue;

    const Vector3 positionB = m_molecule->atomPosition3d(coordinate.b);
    if (coordinate.length > coincidentTolerance &&
        (positionB - positionA).norm() > coincidentTolerance)
      coordinate.angle = calculateAngle(position, positionA, positionB);

    if (coordinate.c == MaxIndex)
      continue;

    const Vector3 positionC = m_molecule->atomPosition3d(coordinate.c);
    if ((positionC - positionB).norm() > coincidentTolerance)
      coordinate.dihedral =
        calculateDihedral(position, positionA, positionB, positionC);
  }

  updateDegenerateRows();

  emit dataChanged(
    index(0, 0),
    index(static_cast<int>(m_coordinates.size()) - 1, ColumnCount - 1));
}

bool ZMatrixModel::needsReorder() const
{
  for (size_t row = 0; row < m_rowToAtom.size(); ++row) {
    if (m_rowToAtom[row] != row)
      return true;
  }
  return false;
}

bool ZMatrixModel::reorderAtoms()
{
  if (m_molecule == nullptr || !needsReorder())
    return false;

  auto* undoMolecule = m_molecule->undoMolecule();
  if (undoMolecule == nullptr)
    return false;

  // reorderAtoms() takes, for each new index, the atom currently there --
  // which is exactly what the row-to-atom map already is.
  if (!undoMolecule->reorderAtoms(m_rowToAtom))
    return false;

  m_molecule->emitChanged(Molecule::Atoms | Molecule::Bonds |
                          Molecule::Modified);
  rebuildStructure();
  return true;
}

void ZMatrixModel::updateDegenerateRows()
{
  m_degenerate = false;

  for (size_t row = 0; row < m_coordinates.size(); ++row) {
    const Core::InternalCoordinate& coordinate = m_coordinates[row];
    // The opening rows are short of references because there are not yet
    // atoms to measure against, which no dummy atom would change.
    if (coordinate.a == MaxIndex || coordinate.b == MaxIndex)
      continue;

    // A straight row carries no plane of its own, so neither its angle nor
    // any dihedral taken from it can be edited. A row with three atoms
    // before it and no 'c' found none of them off the axis.
    if (std::abs(std::sin(coordinate.angle * DEG_TO_RAD)) <=
          straightTolerance ||
        (row >= 3 && coordinate.c == MaxIndex)) {
      m_degenerate = true;
      return;
    }
  }
}

bool ZMatrixModel::needsDummyAtoms() const
{
  return m_degenerate;
}

bool ZMatrixModel::addDummyAtoms()
{
  if (m_molecule == nullptr)
    return false;

  const Core::Array<Core::DummyAtomSite> sites =
    Core::linearDummySites(*m_molecule);
  if (sites.empty())
    return false;

  auto* undoMolecule = m_molecule->undoMolecule();
  if (undoMolecule == nullptr)
    return false;

  // One undo step for the lot: they are one answer to one question, and
  // taking them back one at a time would leave the matrix half propped up.
  undoMolecule->beginMergeMode(tr("Add Dummy Atoms"));
  for (const auto& site : sites) {
    if (site.anchor >= undoMolecule->atomCount())
      continue;
    const auto dummy = undoMolecule->addAtom(0, site.position);
    // Bonding each dummy to its anchor is what keeps it where it is useful:
    // an unbonded one would be a fragment of its own, and every edit
    // elsewhere in the molecule would walk off and leave it behind.
    undoMolecule->addBond(site.anchor, dummy.index(), 1);
  }
  undoMolecule->endMergeMode();

  // Emitting the change rebuilds the table through updateTable(), since the
  // atom and bond counts have both moved.
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Bonds | Molecule::Added);
  return true;
}

bool ZMatrixModel::rebuildGeometry()
{
  if (m_molecule == nullptr || m_coordinates.empty())
    return false;

  auto* undoMolecule = m_molecule->undoMolecule();
  if (undoMolecule == nullptr)
    return false;

  const Core::Array<Vector3> positions = Core::internalToCartesian(
    *m_molecule, m_coordinates, m_rowToAtom, Core::ZMatrixOrigin::Preserve);
  if (positions.size() != m_molecule->atomCount())
    return false;

  undoMolecule->setAtomPositions3d(positions, tr("Rebuild from Z-matrix"));
  m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
  refreshValues();
  return true;
}

} // namespace Avogadro::QtPlugins
