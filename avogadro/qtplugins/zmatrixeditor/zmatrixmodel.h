/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ZMATRIXMODEL_H
#define AVOGADRO_QTPLUGINS_ZMATRIXMODEL_H

#include <QtCore/QAbstractTableModel>

#include <avogadro/core/array.h>
#include <avogadro/core/internalcoordinates.h>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

/**
 * @brief A z-matrix over the molecule's atoms, one row per atom.
 *
 * Rows are in z-matrix order, which need not be the molecule's atom order:
 * each row's reference atoms are guaranteed to appear in an earlier row. The
 * vertical header carries the atom number a row places, so it reads the same
 * way as the reference columns.
 *
 * The references a row is measured against are kept as the user leaves them
 * and only rebuilt when the molecule's atoms or bonds change. A geometry
 * change recomputes the values against those same references, so moving an
 * atom elsewhere in the application does not silently re-derive the matrix
 * underneath the person editing it.
 */
class ZMatrixModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  explicit ZMatrixModel(QObject* parent = nullptr);

  enum Column
  {
    ElementColumn = 0,
    AColumn,
    DistanceColumn,
    BColumn,
    AngleColumn,
    CColumn,
    DihedralColumn,
    ColumnCount
  };

  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index, int role) const override;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole) override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const override;

  void setMolecule(QtGui::Molecule* molecule);

  /** The molecule atom the given row places, or MaxIndex. */
  Index atomForRow(int row) const;

  /** The row that places the given atom, or -1. */
  int rowForAtom(Index atom) const;

  /**
   * True when the molecule's atom order is not already a valid z-matrix
   * order, so that renumbering it would change something.
   */
  bool needsReorder() const;

  /**
   * Renumber the molecule's atoms into z-matrix order, as one undoable step.
   * @return False if there was nothing to do.
   */
  bool reorderAtoms();

  /**
   * Rebuild every atom position from the matrix as it now stands, as one
   * undoable step. The molecule is not moved or reoriented: the placement
   * the first rows would otherwise be free to choose is taken from where the
   * molecule already sits.
   */
  bool rebuildGeometry();

signals:
  /**
   * A reference the user typed was refused. @p reason says why, in terms
   * meant for a status line rather than a log.
   */
  void referenceRejected(const QString& reason);

public slots:
  void updateTable(unsigned int changes);

  /**
   * Tell the model whether anyone is looking. While inactive it records that
   * the molecule moved and does no work; becoming active catches it up.
   */
  void setActive(bool active);

private:
  /** Re-derive the row order and every row's references from the molecule. */
  void rebuildStructure();

  /** Recompute the values only, against the references already in place. */
  void refreshValues();

  /**
   * Why @p reference may not be used by @p row, or an empty string if it
   * may. A reference has to be a real atom, different from the row's own
   * atom and from the row's other references, and placed by an earlier row.
   */
  QString referenceError(int row, Index reference, Column column) const;

  /**
   * The reference a column depends on: the one whose absence leaves the
   * column blank and uneditable. Returns MaxIndex for the element column,
   * which never depends on one.
   */
  static Index gatingReference(const Core::InternalCoordinate& coordinate,
                               int column);

  QtGui::Molecule* m_molecule = nullptr;
  Core::Array<Core::InternalCoordinate> m_coordinates;
  Core::Array<Index> m_rowToAtom;

  // The bond count tells a geometry change from one that invalidates the row
  // order and the references. The atom count needs no separate copy: there
  // is exactly one row per atom.
  Index m_lastBondCount = 0;

  // Recomputing the table for a dock nobody is looking at costs an acos and
  // an atan2 per atom on every molecule signal, so the work is deferred
  // until the dock is shown.
  bool m_active = false;
  bool m_dirty = true;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ZMATRIXMODEL_H
