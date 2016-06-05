/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "spacegroupdialog.h"

#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <QStandardItemModel>
#include <string>
#include <vector>

#include <QtWidgets/QPlainTextEdit>
#include <QtCore/QRegExp>
#include <QList>
#include <QColumnView>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QDebug>

/*class spgColumnView : public QColumnView
{
  public:
    spgColumnView(QWidget* p) : QColumnView(p) {}
    QAbstractItemView * createColumn ( const QModelIndex & index )
    {
      Avogadro::QtPlugins::SpaceGroupItem *thisItem = static_cast<Avogadro::QtPlugins::SpaceGroupItem*>(index.internalPointer());
      QAbstractItemView *view = 0;
      if(thisItem->childCount() == 0)
        return view;
      else
        return QColumnView::createColumn(index);
    }
};*/
#include "ui_spacegroupdialog.h"

using Avogadro::Core::UnitCell;
using Avogadro::Core::SpaceGroups;
using Avogadro::Core::CrystalTools;
using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

SpaceGroupDialog::SpaceGroupDialog(QWidget *p) :
  QDialog(p),
  m_ui(new Ui::SpaceGroupDialog),
  m_molecule(NULL)
{
  m_ui->setupUi(this);

  connect(m_ui->apply, SIGNAL(clicked()), SLOT(apply()));
  connect(m_ui->revert, SIGNAL(clicked()), SLOT(revert()));
  connect(m_ui->columnView, SIGNAL(clicked(QModelIndex)),
      this, SLOT(selectSpaceGroup()));
  connect(m_ui->search, SIGNAL(textChanged(QString)),
      this, SLOT(search()));

  /*
  QList<int> widths;
  widths << 128 << 20 << 128 << 50;
  m_ui->columnView->setColumnWidths(widths);

  QStandardItemModel *mySpg = setSpaceGroups(this);
  m_ui->columnView->setModel(mySpg);
  */

  QList<int> widths;
  widths.append(150);
  widths.append(150);
  widths.append(150);
  widths.append(150);
  widths.append(150);
  widths.append(150);
  m_ui->columnView->setColumnWidths(widths);

  mySpg = new SpaceGroupModel(this);
  m_ui->columnView->setModel(mySpg);
  m_ui->text->setText("select group");


}

SpaceGroupDialog::~SpaceGroupDialog()
{
  delete m_ui;
}

void SpaceGroupDialog::setMolecule(QtGui::Molecule *molecule)
{
  if (molecule != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = molecule;

    if (m_molecule)
      connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));

    revert();
  }
}

void SpaceGroupDialog::moleculeChanged(unsigned int changes)
{
  if (changes & Molecule::UnitCell)
    revert();
}


void SpaceGroupDialog::apply()
{
  if (!isCrystal()) {
    revert();
    return;
  }

  QVariant selectedGroup = mySpg->data(m_ui->columnView->currentIndex(),20);

  CrystalTools::setSpaceGroup(*m_molecule,selectedGroup.toInt());


  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}

void SpaceGroupDialog::revert()
{
  if (isCrystal())
    m_tempCell = *m_molecule->unitCell();

  //revert spacegroup

}

void SpaceGroupDialog::selectSpaceGroup()
{
  //QString current = m_ui->text->toPlainText();
  QVariant selectedGroup = mySpg->data(m_ui->columnView->currentIndex(),200);
  if(selectedGroup.toString()!="")
    m_ui->text->setText(selectedGroup.toString());
}

void SpaceGroupDialog::search()
{
  //qDebug() << "searching for " << m_ui->search->text();
  //mySpg->match
  return;
}


bool SpaceGroupDialog::isCrystal() const
{
  return m_molecule && m_molecule->unitCell();
}

void SpaceGroupDialog::enableApply(bool e)
{
  m_ui->apply->setEnabled(e);
}

void SpaceGroupDialog::enableRevert(bool e)
{
  m_ui->revert->setEnabled(e);
}

/*
void SpaceGroupDialog::initializeMatrixEditor(QPlainTextEdit *edit)
{
#ifdef Q_WS_X11
  QFont font("Monospace");
#else
  QFont font("Courier");
#endif
  edit->setFont(font);

  QFontMetrics metrics(font);
  int minWidth = 3 * metrics.width('0') * (MATRIX_WIDTH + 1);
  int minHeight = metrics.lineSpacing() * 3;

  edit->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum);
  edit->setMinimumSize(minWidth, minHeight);
}

bool SpaceGroupDialog::validateMatrixEditor(QPlainTextEdit *edit)
{
  bool valid = stringToMatrix(edit->toPlainText()) != Matrix3::Zero();
  QPalette pal = edit->palette();
  pal.setColor(QPalette::Text, valid ? Qt::black : Qt::red);
  edit->setPalette(pal);
  return valid;
}
*/

/*QStandardItemModel* SpaceGroupDialog::setSpaceGroups(QObject* parent){

  std::vector<SpaceGroups::crystalSystem> crystals = SpaceGroups::getCrystalArray();

  QStandardItemModel* model = new QStandardItemModel(parent);
  for (int i=0;i<crystals.size();i++)
  {
    SpaceGroups::crystalSystem iCrystal = crystals.at(i);
    QString crystal = QString::fromStdString(SpaceGroups::getCrystalString(iCrystal));

    QStandardItem* crystalNode = new QStandardItem(crystal);
    std::vector<std::string> bravais = SpaceGroups::getBravaisArray(iCrystal);
    for (int j=0;j<bravais.size();j++)
    {
      QString bravaisStr = QString::fromStdString(bravais.at(j));
      QStandardItem* bravaisNode = new QStandardItem(bravaisStr);
      crystalNode->appendRow(bravaisNode);
      std::vector<std::string> intSymbol = SpaceGroups::getIntSymbolArray(iCrystal,bravais.at(j));
      for (int k=0;k<intSymbol.size();k++)
      {
        QString intString = QString::fromStdString(intSymbol.at(k));
        QStandardItem* intNode = new QStandardItem(intString);
        bravaisNode->appendRow(intNode);
        std::vector<std::string> settings = SpaceGroups::getSettingArray(iCrystal,bravais.at(j),intSymbol.at(k));
        for (int l=0;l<settings.size();l++)
        {
          if(settings.at(l) != "     ")
          {
            QString settingString = QString::fromStdString(settings.at(l));
            QStandardItem* settingNode = new QStandardItem(settingString);
            intNode->appendRow(settingNode);
          }
        }
      }
    }


    model->setItem(i,crystalNode);
  }
    return model;
}*/

} // namespace QtPlugins
} // namespace Avogadro

//#include "spacegroupdialog.moc"
