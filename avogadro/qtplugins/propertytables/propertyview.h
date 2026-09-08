/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PROPERTYVIEW_H
#define AVOGADRO_QTPLUGINS_PROPERTYVIEW_H

#include "propertymodel.h"

#include <QtWidgets/QTableView>

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
