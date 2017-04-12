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
#include <QtCore/QSettings>

namespace {
// The ItemData of the "Other" entry in the combo box
const int ELEMENT_SELECTOR_TAG = 255;
}

namespace Avogadro {
namespace QtPlugins {

EditorToolWidget::EditorToolWidget(QWidget* parent_)
  : QWidget(parent_), m_ui(new Ui::EditorToolWidget),
    m_elementSelector(nullptr), m_currentElement(6)
{
  m_ui->setupUi(this);

  buildElements();
  buildBondOrders();

  connect(m_ui->element, SIGNAL(currentIndexChanged(int)), this,
          SLOT(elementChanged(int)));

  // Show carbon at startup.
  selectElement(6);
}

EditorToolWidget::~EditorToolWidget()
{
  delete m_ui;
}

void EditorToolWidget::setAtomicNumber(unsigned char atomicNum)
{
  selectElement(atomicNum);

  if (m_elementSelector)
    m_elementSelector->setElement(static_cast<int>(atomicNum));
}

unsigned char EditorToolWidget::atomicNumber() const
{
  int curIndex = m_ui->element->currentIndex();
  QVariant itemData = m_ui->element->itemData(curIndex);
  if (!itemData.isValid())
    return 0;

  unsigned char atomicNum = static_cast<unsigned char>(itemData.toUInt());

  // "Other..." selected....
  if (atomicNum == 0 && m_elementSelector)
    atomicNum = static_cast<unsigned char>(m_elementSelector->element());

  return atomicNum;
}

void EditorToolWidget::setBondOrder(unsigned char order)
{
  if (order < m_ui->bondOrder->count())
    m_ui->bondOrder->setCurrentIndex(static_cast<int>(order));
}

unsigned char EditorToolWidget::bondOrder() const
{
  return static_cast<unsigned char>(m_ui->bondOrder->currentIndex());
}

bool EditorToolWidget::adjustHydrogens() const
{
  return m_ui->adjustHydrogens->isChecked();
}

void EditorToolWidget::elementChanged(int index)
{
  QVariant itemData = m_ui->element->itemData(index);
  if (itemData.isValid()) {
    if (itemData.toInt() == ELEMENT_SELECTOR_TAG) {
      if (!m_elementSelector) {
        m_elementSelector = new QtGui::PeriodicTableView(this);
        connect(m_elementSelector, SIGNAL(elementChanged(int)), this,
                SLOT(elementSelectedFromTable(int)));
      }
      m_elementSelector->setElement(m_currentElement);
      m_elementSelector->show();
    } else {
      if (m_elementSelector)
        m_elementSelector->setElement(itemData.toInt());
      m_currentElement = static_cast<unsigned char>(itemData.toInt());
    }
  }
}

void EditorToolWidget::updateElementCombo()
{
  // Build set of all elements:
  QList<unsigned char> allElements;
  allElements << m_defaultElements;
  allElements << m_userElements;
  qSort(allElements);

  // Cache selected atomic number for later
  QVariant selectedData;
  int curIndex = m_ui->element->currentIndex();
  if (curIndex >= 0)
    selectedData = m_ui->element->itemData(curIndex);

  // Clear and repopulate combo
  m_ui->element->clear();
  foreach (unsigned char atomicNum, allElements) {
    m_ui->element->addItem(
      QString("%1 (%2)").arg(Core::Elements::name(atomicNum)).arg(atomicNum),
      atomicNum);
  }
  m_ui->element->insertSeparator(m_ui->element->count());
  m_ui->element->addItem(tr("Other..."), ELEMENT_SELECTOR_TAG);

  // Reset the element if it still exists
  selectElement(static_cast<unsigned char>(
    selectedData.isValid() ? selectedData.toInt() : -1));
}

void EditorToolWidget::addUserElement(unsigned char element)
{
  // Never add any of the common elements to the user list.
  if (m_defaultElements.contains(element))
    return;

  // If the element is already in the user list, move it to the back of the
  // list.
  if (m_userElements.removeOne(element)) {
    m_userElements << element;
    return;
  }

  m_userElements << element;

  // Limit the number of user elements
  /// @todo Make this number of user elements configurable.
  while (m_userElements.size() > 15)
    m_userElements.pop_front();

  updateElementCombo();
  saveElements();
}

void EditorToolWidget::elementSelectedFromTable(int element)
{
  addUserElement(static_cast<unsigned char>(element));
  selectElement(static_cast<unsigned char>(element));
}

void EditorToolWidget::selectElement(unsigned char element)
{
  int curIndex = element > 0 ? m_ui->element->findData(element) : -1;
  if (curIndex >= 0)
    m_ui->element->setCurrentIndex(curIndex);
  else {
    addUserElement(element);
    int curIndex = m_ui->element->findData(element);
    if (curIndex >= 0)
      m_ui->element->setCurrentIndex(curIndex);
    // if we can't find it after adding it, something is very wrong!
  }
}

void EditorToolWidget::buildElements()
{
  // Common elements that are always shown in the combo box.
  if (m_defaultElements.isEmpty()) {
    m_defaultElements.append(1);  // Hydrogen
    m_defaultElements.append(5);  // Boron
    m_defaultElements.append(6);  // Carbon
    m_defaultElements.append(7);  // Nitrogen
    m_defaultElements.append(8);  // Oxygen
    m_defaultElements.append(9);  // Fluorine
    m_defaultElements.append(15); // Phosphorus
    m_defaultElements.append(16); // Sulfur
    m_defaultElements.append(17); // Chlorine
    m_defaultElements.append(35); // Bromine
  }

  // User-added elements
  QVariantList userElementsVar =
    QSettings().value("editortool/userElements").toList();
  foreach (const QVariant& var, userElementsVar)
    m_userElements << static_cast<unsigned char>(var.toUInt());

  updateElementCombo();
}

void EditorToolWidget::buildBondOrders()
{
  m_ui->bondOrder->clear();
  m_ui->bondOrder->addItem(tr("Automatic"), 0);
  m_ui->bondOrder->addItem(tr("Single"), 1);
  m_ui->bondOrder->addItem(tr("Double"), 2);
  m_ui->bondOrder->addItem(tr("Triple"), 3);
}

void EditorToolWidget::saveElements()
{
  QVariantList atomicNums;
  for (int i = 0; i < m_userElements.size(); ++i)
    atomicNums << QVariant(m_userElements[i]);

  QSettings().setValue("editortool/userElements", atomicNums);
}

} // namespace QtPlugins
} // namespace Avogadro
