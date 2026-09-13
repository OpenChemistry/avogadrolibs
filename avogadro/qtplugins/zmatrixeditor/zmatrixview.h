/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ZMATRIXVIEW_H
#define AVOGADRO_QTPLUGINS_ZMATRIXVIEW_H

#include <QtWidgets/QTableView>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

class ZMatrixModel;

/**
 * @brief The z-matrix table, kept in step with the selection in the 3D view.
 */
class ZMatrixView : public QTableView
{
  Q_OBJECT

public:
  explicit ZMatrixView(QWidget* parent = nullptr);

  void setMolecule(QtGui::Molecule* molecule);
  void setZMatrixModel(ZMatrixModel* model);

protected slots:
  void selectionChanged(const QItemSelection& selected,
                        const QItemSelection& deselected) override;

  /** Mirror a selection made in the 3D view into the table. */
  void updateSelectionFromMolecule(unsigned int changes);

private:
  QtGui::Molecule* m_molecule = nullptr;
  ZMatrixModel* m_model = nullptr;

  // Selecting rows sets the molecule's selection, which signals back here.
  // Without this the two would chase each other.
  bool m_updatingSelection = false;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ZMATRIXVIEW_H
