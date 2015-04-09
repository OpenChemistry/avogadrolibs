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
#include "ui_spacegroupdialog.h"


#include <avogadro/qtgui/molecule.h>

#include "spacegroupmodel.h"

#include <avogadro/core/crystaltools.h>
#include <avogadro/core/spacegroups.h>
#include <avogadro/core/unitcell.h>
#include <QStandardItemModel>
#include <string>
#include <vector>

#include <QtWidgets/QPlainTextEdit>

#include <QtCore/QRegExp>
#include <QList>

using Avogadro::Core::UnitCell;
using Avogadro::Core::SpaceGroups;
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

  /*
  QList<int> widths;
  widths << 128 << 20 << 128 << 50;
  m_ui->columnView->setColumnWidths(widths);

  QStandardItemModel *mySpg = setSpaceGroups(this);
  m_ui->columnView->setModel(mySpg);
  */


  SpaceGroupModel *mySpg = new SpaceGroupModel::SpaceGroupModel(this);
  m_ui->treeView->setModel(mySpg);


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

  m_molecule->emitChanged(Molecule::Modified
                          | Molecule::Atoms | Molecule::UnitCell);
}

void SpaceGroupDialog::revert()
{
  if (isCrystal())
    m_tempCell = *m_molecule->unitCell();

  //revert spacegroup

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

QStandardItemModel* SpaceGroupDialog::setSpaceGroups(QObject* parent){

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
}

} // namespace QtPlugins
} // namespace Avogadro
