/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PROPERTYVIEW_H
#define AVOGADRO_QTPLUGINS_PROPERTYVIEW_H

#include "propertymodel.h"

#include <QtWidgets/QTableView>

class QDragEnterEvent;
class QDragMoveEvent;
class QDropEvent;
class QProgressDialog;
namespace Avogadro {

namespace QtGui {
class Molecule;
}

class PropertyView : public QTableView
{
  Q_OBJECT
public:
  explicit PropertyView(PropertyType type, QWidget* parent = nullptr);

  void selectionChanged(const QItemSelection& selected,
                        const QItemSelection& previous) override;
  void setMolecule(QtGui::Molecule* molecule);
  void setSourceModel(PropertyModel* model) { m_model = model; }
  void hideEvent(QHideEvent* event) override;
  void contextMenuEvent(QContextMenuEvent* event) override;

public slots:
  /**
   * Move the selection to the molecule's active coordinate set. Only does
   * anything for the conformer table; call it once the model is attached.
   */
  void syncConformerSelection();

private slots:
  /** Follow conformer changes made by the player tool or the conformer plot. */
  void moleculeChanged(unsigned int changes);

protected:
  // copy the selected properties to the clipboard
  void keyPressEvent(QKeyEvent* event) override;
  bool edit(const QModelIndex& index, EditTrigger trigger,
            QEvent* event) override;

  // Drag-to-reorder atom rows. Handled here at the view level rather than
  // through the model's dropMimeData()/MIME machinery.
  void startDrag(Qt::DropActions supportedActions) override;
  void dragEnterEvent(QDragEnterEvent* event) override;
  void dragMoveEvent(QDragMoveEvent* event) override;
  void dropEvent(QDropEvent* event) override;

private:
  PropertyType m_type;
  QtGui::Molecule* m_molecule;
  PropertyModel* m_model;
  bool m_updatingSelection = false;
  bool m_inColorEdit = false;

  // The view can be sorted, so a view row is not the entity index. These map
  // between the two without going through the (localized) header text.
  int sourceRow(const QModelIndex& viewIndex) const;
  int viewRowForSource(int sourceRow) const;

  // True when the atom table can currently offer drag-to-reorder. Under a
  // sort, a dragged row would just jump back to wherever the sort puts it,
  // so reordering is only offered when rows are shown in index order.
  bool rowDragAllowed() const;
  // True when the proxy model (if any) presents rows in source order.
  bool isNaturalOrder() const;
  // Common gate for the drag handlers: only an internal drag on an atom
  // table in index order can reorder rows. Ignores @p event and returns
  // false when the drag is not ours to handle.
  bool dragIsOurs(QDropEvent* event);
  // Insertion index in [0, atomCount()] for a drop at @p pos.
  int dropTargetRow(const QPoint& pos) const;
  // Move the atom currently at row @p from to insertion point @p to,
  // renumbering the molecule undoably. Returns false if the move is a no-op
  // or the underlying reorder was rejected.
  bool moveAtomRow(int from, int to);

  // Conformer table keyboard navigation. Returns true if @p event was used.
  bool conformerKeyPressed(QKeyEvent* event);

  void copySelectedRowsToClipboard();
  void openExportDialogBox();
  void addProperty();
  void constrainSelectedRows();
  void unconstrainSelectedRows();

  void setFrozen(bool frozen);
  void freezeAtom();
  void unfreezeAtom();
  void freezeX();
  void freezeY();
  void freezeZ();
  void freezeAxis(int axis);
  void changeChargeType();
};

} // end namespace Avogadro

#endif
