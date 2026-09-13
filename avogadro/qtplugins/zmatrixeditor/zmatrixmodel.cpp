/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "zmatrixmodel.h"

#include <avogadro/core/angletools.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/fragmenttools.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QtCore/QCoreApplication>

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

  if (role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  // A row near the top of the matrix has fewer than three references, since
  // there are not yet three atoms to measure against. Those cells are empty
  // rather than zero: there is no value, as opposed to a value of nothing.
  if (index_.column() == ElementColumn)
    return QString(Core::Elements::symbol(m_molecule->atomicNumber(atom)));

  if (gatingReference(coordinate, index_.column()) == MaxIndex)
    return QString();

  switch (index_.column()) {
    case AColumn:
      return QString::number(coordinate.a + 1);
    case BColumn:
      return QString::number(coordinate.b + 1);
    case CColumn:
      return QString::number(coordinate.c + 1);
    case DistanceColumn:
      return QString::number(coordinate.length, 'f', distanceDecimals);
    case AngleColumn:
      return QString::number(coordinate.angle, 'f', angleDecimals);
    case DihedralColumn:
      return QString::number(coordinate.dihedral, 'f', angleDecimals);
    default:
      return QVariant();
  }
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
