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

#include "editortoolwidget.h"
#include "ui_editortoolwidget.h"

#include <avogadro/core/elements.h>

#include <avogadro/qtgui/periodictableview.h>

#include <QtCore/QList>
#include <QtCore/QSet>
#include <QtCore/QSettings>

namespace Avogadro {
namespace QtPlugins {

EditorToolWidget::EditorToolWidget(QWidget *parent_) :
  QWidget(parent_),
  m_ui(new Ui::EditorToolWidget),
  m_elementSelector(new QtGui::PeriodicTableView(this))
{
  m_ui->setupUi(this);
  buildElements();
  buildBondOrders();

  connect(m_ui->element, SIGNAL(currentIndexChanged(int)),
          this, SLOT(elementChanged(int)));
  connect(m_elementSelector, SIGNAL(elementSelected(int)),
          this, SLOT(tableDoubleClicked(int)));
}

EditorToolWidget::~EditorToolWidget()
{
  delete m_ui;
}

unsigned short EditorToolWidget::atomicNumber() const
{
  int curIndex = m_ui->element->currentIndex();
  QVariant itemData = m_ui->element->itemData(curIndex);
  if (!itemData.isValid())
    return 0;

  unsigned short atomicNum = static_cast<unsigned short>(itemData.toUInt());

  // "Other..." selected....
  if (atomicNum == 0)
    atomicNum = static_cast<unsigned short>(m_elementSelector->element());

  return atomicNum;
}

unsigned short EditorToolWidget::bondOrder() const
{
  return static_cast<unsigned short>(
        m_ui->bondOrder->itemData(m_ui->bondOrder->currentIndex()).toUInt());
}

void EditorToolWidget::elementChanged(int index)
{
  QVariant itemData = m_ui->element->itemData(index);
  if (itemData.isValid() && itemData.toUInt() == 0)
    m_elementSelector->show();
  else
    m_elementSelector->setElement(itemData.toInt());
}

void EditorToolWidget::tableDoubleClicked(int atomicNum)
{
  // Insert the element into the combo box.

  // Is the atomic number valid?
  if (atomicNum <= 0 || atomicNum > Core::Elements::elementCount())
    return;

  // Find the index to insert at -- maintain increasing atomic number.
  int index = 0;
  for (int eleCount = m_ui->element->count(); index < eleCount; ++index) {
    QVariant itemData = m_ui->element->itemData(index);
    // Stop if we've hit the separator
    if (!itemData.isValid())
      break;

    // Extract the atomic number from the current item
    bool ok = false;
    int curAtomicNum = itemData.toInt(&ok);

    // Stop if we've hit an invalid item, or one with a higher atomic number
    if (!ok || curAtomicNum <= 0 || curAtomicNum > atomicNum) {
      break;

    // If this element already exists in the combo, bail out.
    if (curAtomicNum == atomicNum)
      return;
    }
  }

  // Insert and select the element.
  m_ui->element->insertItem(index, QString("%1 (%2)")
                            .arg(Core::Elements::name(atomicNum))
                            .arg(atomicNum), atomicNum);
  m_ui->element->setCurrentIndex(index);

  saveElements();
}

void EditorToolWidget::buildElements()
{
  m_ui->element->clear();

  QVariantList visibleElementsVar =
      QSettings().value("editortool/visibleElements").toList();
  QList<unsigned short> visibleElements;
  foreach (const QVariant &var, visibleElementsVar)
    visibleElements << var.toUInt();

  if (visibleElements.isEmpty()) {
    visibleElements.append(1);  // Hydrogen
    visibleElements.append(5);  // Boron
    visibleElements.append(6);  // Carbon
    visibleElements.append(7);  // Nitrogen
    visibleElements.append(8);  // Oxygen
    visibleElements.append(9);  // Fluorine
    visibleElements.append(15); // Phosphorus
    visibleElements.append(16); // Sulfur
    visibleElements.append(17); // Chlorine
    visibleElements.append(35); // Bromine
  }

  qSort(visibleElements);
  foreach (unsigned short atomicNum, visibleElements) {
    m_ui->element->addItem(QString("%1 (%2)")
                           .arg(Core::Elements::name(atomicNum))
                           .arg(atomicNum), atomicNum);
  }
  m_ui->element->insertSeparator(m_ui->element->count());
  m_ui->element->addItem(tr("Other..."), 0);
}

void EditorToolWidget::buildBondOrders()
{
  m_ui->bondOrder->clear();
  m_ui->bondOrder->addItem(tr("Single"), 1);
  m_ui->bondOrder->addItem(tr("Double"), 2);
  m_ui->bondOrder->addItem(tr("Triple"), 3);
}

void EditorToolWidget::saveElements()
{
  QVariantList atomicNums;
  for (int i = 0, eleCount = m_ui->element->count(); i < eleCount; ++i) {
    QVariant var = m_ui->element->itemData(i);
    if (var.isValid()) {
      int atomicNum = var.toInt();
      if (atomicNum > 0 && atomicNum <= Core::Elements::elementCount())
        atomicNums << atomicNum;
    }
  }
  QSettings().setValue("editortool/visibleElements", atomicNums);
}

} // namespace QtPlugins
} // namespace Avogadro
