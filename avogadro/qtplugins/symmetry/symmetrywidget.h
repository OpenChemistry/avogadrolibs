/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2015 Marcus Johansson <mcodev31@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SYMMETRYWIDGET_H
#define AVOGADRO_QTPLUGINS_SYMMETRYWIDGET_H

#include <QtWidgets/QWidget>

#include <QVector3D>

#include <avogadro/core/avogadrocore.h>

#include <QItemSelection>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStyledItemDelegate>

#include "operationstablemodel.h"
#include "symmetrywidget.h"

// class QPlainTextEdit;

namespace msym {
extern "C" {
#include <libmsym/msym.h>
}
}

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SymmetryWidget;
}

/**
 * @brief The SymmetryWidget class provides a widget for handling symmetry
 * unit cell.
 */
class SymmetryWidget : public QWidget
{
  Q_OBJECT

public:
  explicit SymmetryWidget(QWidget* parent = 0);
  ~SymmetryWidget() override;

  void setMolecule(QtGui::Molecule* molecule);

signals:
  void detectSymmetry();
  void symmetrizeMolecule();

public slots:
  void moleculeChanged(unsigned int changes);

  void setPointGroupSymbol(QString pg);
  void setSymmetryOperations(int sopsl, msym::msym_symmetry_operation_t* sops);
  void setSubgroups(int sgl, msym::msym_subgroup_t* sg);
  void setCenterOfMass(double cm[3]);
  void setRadius(double radius);
  msym::msym_thresholds_t* getThresholds() const;

private slots:
  void operationsSelectionChanged(const QItemSelection& selected,
                                  const QItemSelection& deselected);
  void subgroupsSelectionChanged(const QItemSelection& selected,
                                 const QItemSelection& deselected);

private:
  Ui::SymmetryWidget* m_ui;
  OperationsTableModel* m_operationsTableModel;
  QStandardItemModel* m_subgroupsTreeModel;
  QtGui::Molecule* m_molecule;
  QVector3D m_cm;

  msym::msym_symmetry_operation_t* m_sops;
  msym::msym_subgroup_t* m_sg;
  int m_sopsl, m_sgl;
  double m_radius;

  void addSubgroup(QStandardItem*, msym::msym_subgroup_t*);
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SYMMETRYWIDGET_H
