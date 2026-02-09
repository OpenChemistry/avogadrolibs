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
  void copySelectedRowsToClipboard();
  void openExportDialogBox();
  void constrainSelectedRows();
  void unconstrainSelectedRows();

  void setFrozen(bool frozen);
  void freezeAtom();
  void unfreezeAtom();
  void freezeX();
  void freezeY();
  void freezeZ();
  void freezeAxis(int axis);
};

} // end namespace Avogadro

#endif
