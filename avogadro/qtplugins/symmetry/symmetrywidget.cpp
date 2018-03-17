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

#include "symmetrywidget.h"
#include "richtextdelegate.h"
#include "symmetryutil.h"
#include "ui_symmetrywidget.h"

#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QRegExp>
#include <QtWidgets/QPlainTextEdit>

using Avogadro::QtGui::Molecule;

using namespace msym;
using namespace Avogadro::QtPlugins::SymmetryUtil;

namespace Avogadro {
namespace QtPlugins {

msym_thresholds_t tight_thresholds = { // all defaults
  /*.zero =*/1.0e-3,
  /*.geometry =*/1.0e-3,
  /*.angle =*/1.0e-3,
  /*.equivalence =*/5.0e-4,
  /*.eigfact =*/1.0e-3,
  /*.permutation =*/5.0e-3,
  /*.orthogonalization =*/0.1
};

msym_thresholds_t medium_thresholds = {
  /*.zero =*/1.0e-2,
  /*.geometry =*/1.0e-2,
  /*.angle =*/1.0e-2,
  /*.equivalence =*/6.3e-3,
  /*.eigfact =*/1.0e-3,
  /*.permutation =*/1.58e-2,
  /*.orthogonalization =*/0.1
};

msym_thresholds_t loose_thresholds = {
  /*.zero =*/0.06,
  /*.geometry =*/0.06,
  /*.angle =*/0.06,
  /*.equivalence =*/0.025,
  /*.eigfact =*/1.0e-3,
  /*.permutation =*/1.0e-1,
  /*.orthogonalization =*/0.1
};

msym_thresholds_t sloppy_thresholds = {
  /*.zero =*/0.08,
  /*.geometry =*/0.1,
  /*.angle =*/0.1,
  /*.equivalence =*/0.06,
  /*.eigfact =*/1.0e-3,
  /*.permutation =*/1.0e-1,
  /*.orthogonalization =*/0.1
};

SymmetryWidget::SymmetryWidget(QWidget* parent_)
  : QWidget(parent_), m_ui(new Ui::SymmetryWidget), m_molecule(NULL),
    m_operationsTableModel(new OperationsTableModel(this)),
    m_subgroupsTreeModel(new QStandardItemModel(this)), m_sops(NULL),
    m_sg(NULL), m_sopsl(0), m_sgl(0), m_radius(0.0)
{
  setWindowFlags(Qt::Dialog);
  m_ui->setupUi(this);
  m_ui->operationsTable->setModel(m_operationsTableModel);
  m_ui->operationsTable->setItemDelegateForColumn(
    OperationsTableModel::ColumnType, new RichTextDelegate(this));

  m_ui->subgroupsTree->setModel(m_subgroupsTreeModel);
  m_ui->subgroupsTree->setItemDelegateForColumn(0, new RichTextDelegate(this));

  connect(m_ui->detectSymmetryButton, SIGNAL(clicked()),
          SIGNAL(detectSymmetry()));
  connect(m_ui->symmetrizeMoleculeButton, SIGNAL(clicked()),
          SIGNAL(symmetrizeMolecule()));
  connect(
    m_ui->operationsTable->selectionModel(),
    SIGNAL(selectionChanged(const QItemSelection&, const QItemSelection&)),
    SLOT(operationsSelectionChanged(const QItemSelection&,
                                    const QItemSelection&)));
  connect(
    m_ui->subgroupsTree->selectionModel(),
    SIGNAL(selectionChanged(const QItemSelection&, const QItemSelection&)),
    SLOT(
      subgroupsSelectionChanged(const QItemSelection&, const QItemSelection&)));
}

SymmetryWidget::~SymmetryWidget()
{
  delete m_ui;
}

void SymmetryWidget::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = molecule;

    if (m_molecule) {
      connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));
    }
  }
}

void SymmetryWidget::moleculeChanged(unsigned int changes)
{
  /*
  if (changes & Molecule::UnitCell)
    revert();*/
}

void SymmetryWidget::operationsSelectionChanged(
  const QItemSelection& selected, const QItemSelection& deselected)
{

  if (!m_molecule)
    return;
  if (m_ui->tabWidget->currentWidget() != m_ui->subgroupsTab) {
    qDebug() << "subgroupsTab not selected";
    m_ui->subgroupsTree->selectionModel()->reset();
  } else
    qDebug() << "subgroupsTab selected";

  QModelIndexList selection =
    m_ui->operationsTable->selectionModel()->selectedRows();

  qDebug() << "operations changed";

  qDebug() << "selection " << selection.size();

  QVariantList reflectionVariantList;
  QVariantList properRotationVariantList;
  QVariantList improperRotationVariantList;

  m_molecule->setProperty("SymmetryOrigo", QVariant());
  m_molecule->setProperty("SymmetryRadius", QVariant());
  m_molecule->setProperty("SymmetryInversion", QVariant());
  m_molecule->setProperty("SymmetryProperRotationVariantList", QVariant());
  m_molecule->setProperty("SymmetryImproperRotationVariantList", QVariant());
  m_molecule->setProperty("SymmetryReflectionVariantList", QVariant());

  qDebug() << "cleared elements";

  if (m_sopsl > 0 && selection.size() > 0) {
    m_molecule->setProperty("SymmetryOrigo", m_cm);
    m_molecule->setProperty("SymmetryRadius", m_radius);
  }

  foreach (QModelIndex i, selection) {
    unsigned int row = i.row();
    if (!i.isValid() || row >= m_sopsl)
      continue;
    float x = m_sops[row].v[0], y = m_sops[row].v[1], z = m_sops[row].v[2];
    switch (m_sops[row].type) {
      case IDENTITY:
        break;
      case PROPER_ROTATION:
        properRotationVariantList.append(QVector3D(x, y, z));
        break;
      case IMPROPER_ROTATION:
        improperRotationVariantList.append(QVector3D(x, y, z));
        break;
      case REFLECTION:
        reflectionVariantList.append(QVector3D(x, y, z));
        break;
      case INVERSION:
        m_molecule->setProperty("SymmetryInversion", m_cm);
        break;
      default:
        break;
    }
  }
  if (properRotationVariantList.size() > 0)
    m_molecule->setProperty("SymmetryProperRotationVariantList",
                            properRotationVariantList);
  if (improperRotationVariantList.size() > 0)
    m_molecule->setProperty("SymmetryImproperRotationVariantList",
                            improperRotationVariantList);
  if (reflectionVariantList.size() > 0)
    m_molecule->setProperty("SymmetryReflectionVariantList",
                            reflectionVariantList);

  /* A little bit ugly, but it'll do for now */
  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

void SymmetryWidget::subgroupsSelectionChanged(const QItemSelection& selected,
                                               const QItemSelection& deselected)
{
  // QModelIndexList selection =
  // m_ui->subgroupsTree->selectionModel()->selectedIndexes();
  QModelIndex i =
    m_ui->subgroupsTree->selectionModel()->selectedIndexes().first();
  qDebug() << "subgroupsSelectionChanged";
  if (!i.isValid())
    return;
  qDebug() << "valid";
  int sgi = i.data(Qt::UserRole).value<int>();
  qDebug() << "index " << sgi;
  if (sgi < 0 || sgi >= m_sgl)
    return;
  msym::msym_subgroup_t* sg = &m_sg[sgi];
  // m_ui->operationsTable->selectionModel()->clear();

  QItemSelectionModel* selectionModel = m_ui->operationsTable->selectionModel();
  // selectionModel->clear();

  QItemSelection selection;

  for (int j = 0; j < sg->order; j++) {
    int row = static_cast<int>(sg->sops[j] - m_sops);
    QModelIndex left = m_operationsTableModel->index(row, 0);
    QModelIndex right = m_operationsTableModel->index(
      row, m_operationsTableModel->columnCount(left) - 1);
    if (!left.isValid() || !right.isValid())
      qDebug() << "invalid index " << j;
    QItemSelection sel(left, right);

    selection.merge(sel, QItemSelectionModel::Select);
  }

  QModelIndexList tmp = selection.indexes();
  foreach (QModelIndex j, tmp) {
    qDebug() << "selecting " << j.row() << " " << j.column();
  }

  selectionModel->select(selection, QItemSelectionModel::ClearAndSelect);
}

void SymmetryWidget::setRadius(double radius)
{
  m_radius = radius;
}

void SymmetryWidget::setCenterOfMass(double cm[3])
{
  m_cm = QVector3D(cm[0], cm[1], cm[2]);
}

void SymmetryWidget::setPointGroupSymbol(QString pg)
{
  m_ui->pointGroupLabel->setText(pg);
}

void SymmetryWidget::setSymmetryOperations(
  int sopsl, msym::msym_symmetry_operation_t* sops)
{
  m_sops = sops;
  m_sopsl = sopsl;
  m_operationsTableModel->setOperations(sopsl, sops);
  m_molecule->setProperty("SymmetryOrigo", QVariant());
  m_molecule->setProperty("SymmetryRadius", QVariant());
  m_molecule->setProperty("SymmetryInversion", QVariant());
  m_molecule->setProperty("SymmetryProperRotationVariantList", QVariant());
  m_molecule->setProperty("SymmetryImproperRotationVariantList", QVariant());
  m_molecule->setProperty("SymmetryReflectionVariantList", QVariant());
  /* need another change event */
  m_molecule->emitChanged(QtGui::Molecule::Atoms);
}

#include <stdio.h>

void SymmetryWidget::setSubgroups(int sgl, msym::msym_subgroup_t* sg)
{
  m_sg = sg;
  m_sgl = sgl;
  m_subgroupsTreeModel->clear();
  fprintf(stderr, "setSubgroups\n");
  for (int i = 0; i < sgl; i++) {
    if (sg[i].order <= 2)
      continue;
    fprintf(stderr, "setSubgroups loop\n");
    QStandardItem* const parent = new QStandardItem;
    parent->setText(pointGroupSymbol(sg[i].name));
    parent->setData(i, Qt::UserRole);
    m_subgroupsTreeModel->appendRow(parent);
    for (int j = 0; j < 2; j++) {
      if (sg[i].generators[j] == NULL)
        continue;
      fprintf(stderr, "setChild\n");
      qDebug() << "child " << sg[i].generators[j] - m_sg << " "
               << sg[i].generators[j] << " " << m_sg;
      fprintf(stderr, "%s\n", sg[i].generators[j]->name);
      QStandardItem* const child = new QStandardItem;
      child->setText(pointGroupSymbol(sg[i].generators[j]->name));

      child->setData(static_cast<int>(sg[i].generators[j] - m_sg),
                     Qt::UserRole);
      parent->appendRow(child);
    }
  }
}

msym_thresholds_t* SymmetryWidget::getThresholds() const
{
  msym_thresholds_t* thresholds = NULL;
  switch (m_ui->toleranceCombo->currentIndex()) {
    case 2: // loose
      thresholds = &loose_thresholds;
      break;
    case 1: // normal
      thresholds = &medium_thresholds;
      break;
    case 0: // tight
    default:
      thresholds = &tight_thresholds;
  }
  return thresholds;
}

} // namespace QtPlugins
} // namespace Avogadro
