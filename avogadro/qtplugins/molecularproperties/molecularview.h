/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_MOLECULARVIEW_H
#define AVOGADRO_QTPLUGINS_MOLECULARVIEW_H

#include "molecularmodel.h"

#include <QtWidgets/QTableView>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

class MolecularView : public QTableView
{
  Q_OBJECT
public:
  explicit MolecularView(QWidget* parent = 0);

  void selectionChanged(const QItemSelection& selected,
                        const QItemSelection& previous) override;
  void setMolecule(QtGui::Molecule* molecule);
  void setSourceModel(MolecularModel* model) { m_model = model; }
  void hideEvent(QHideEvent* event) override;
  void contextMenuEvent(QContextMenuEvent* event) override;

protected:
  // copy the selected properties to the clipboard
  void keyPressEvent(QKeyEvent* event) override;

private:
  QtGui::Molecule* m_molecule;
  MolecularModel* m_model;
  void copySelectedRowsToClipboard();
  void openExportDialogBox();
};

} // end namespace Avogadro

#endif
