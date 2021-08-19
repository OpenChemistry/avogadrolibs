/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "templatetoolwidget.h"
#include "ui_templatetoolwidget.h"

#include <avogadro/core/elements.h>

#include <avogadro/qtgui/periodictableview.h>

#include <QtCore/QList>
#include <QtCore/QSettings>

#include <QDebug>

namespace {
// The ItemData of the "Other" entry in the combo box
const int ELEMENT_SELECTOR_TAG = 255;
}

namespace Avogadro {
namespace QtPlugins {



TemplateToolWidget::TemplateToolWidget(QWidget *parent_) :
  QWidget(parent_),
  m_ui(new Ui::TemplateToolWidget),
  m_elementSelector(NULL),
  m_currentElement(26)
{
  m_ui->setupUi(this);

  buildElements();

  connect(m_ui->elementComboBox, SIGNAL(currentIndexChanged(int)),
          this, SLOT(elementChanged(int)));

  connect(m_ui->coordinationComboBox, SIGNAL(currentIndexChanged(int)),
          this, SLOT(coordinationChanged(int)));

  // Show carbon at startup.
  selectElement(6);
  setCoordination(7); // octahedral

  // In the same order of the coordinationComboBox
  // append ".png" for the icon and ".cjson" for the template
  m_centers << "1-lin" << "2-lin" << "3-tpl" << "4-tet" << "4-sqp" << "5-tbp"
  << "5-spy" << "6-oct" << "6-tpr" << "7-pbp" << "8-sqa";
}

TemplateToolWidget::~TemplateToolWidget()
{
  delete m_ui;
}

void TemplateToolWidget::setAtomicNumber(unsigned char atomicNum)
{
  selectElement(atomicNum);

  if (m_elementSelector)
    m_elementSelector->setElement(static_cast<int>(atomicNum));
}

unsigned char TemplateToolWidget::atomicNumber() const
{
  int curIndex = m_ui->elementComboBox->currentIndex();
  QVariant itemData = m_ui->elementComboBox->itemData(curIndex);
  if (!itemData.isValid())
    return 0;

  unsigned char atomicNum = static_cast<unsigned char>(itemData.toUInt());

  // "Other..." selected....
  if (atomicNum == 0 && m_elementSelector)
    atomicNum = static_cast<unsigned char>(m_elementSelector->element());

  return atomicNum;
}

void TemplateToolWidget::setCoordination(unsigned char order)
{
  if (order < m_ui->coordinationComboBox->count())
    m_ui->coordinationComboBox->setCurrentIndex(static_cast<int>(order));
}

unsigned char TemplateToolWidget::coordination() const
{
  return static_cast<unsigned char>(m_ui->coordinationComboBox->currentIndex());
}

QString TemplateToolWidget::coordinationString() const
{
  return m_centers.at(m_ui->coordinationComboBox->currentIndex());
}

void TemplateToolWidget::coordinationChanged(int index)
{
  if (index < 0 || index > m_ui->coordinationComboBox->count())
    return;
  
  // get the icon name
  QString iconName = m_centers[m_ui->coordinationComboBox->currentIndex()];
  qDebug() << "Icon name: " << iconName;
  m_ui->preview->setIcon(QIcon(":/icons/centers/" + iconName + ".png"));
}

void TemplateToolWidget::elementChanged(int index)
{
  QVariant itemData = m_ui->elementComboBox->itemData(index);
  if (itemData.isValid()) {
    if (itemData.toInt() == ELEMENT_SELECTOR_TAG) {
      if (!m_elementSelector) {
        m_elementSelector = new QtGui::PeriodicTableView(this);
        connect(m_elementSelector, SIGNAL(elementChanged(int)),
                this, SLOT(elementSelectedFromTable(int)));
      }
      m_elementSelector->setElement(m_currentElement);
      m_elementSelector->show();
    }
    else {
      if (m_elementSelector)
        m_elementSelector->setElement(itemData.toInt());
      m_currentElement = static_cast<unsigned char>(itemData.toInt());
    }
  }
}

void TemplateToolWidget::updateElementCombo()
{
  // Build set of all elements:
  QList<unsigned char> allElements;
  allElements << m_defaultElements;
  allElements << m_userElements;
  qSort(allElements);

  // Cache selected atomic number for later
  QVariant selectedData;
  int curIndex = m_ui->elementComboBox->currentIndex();
  if (curIndex >= 0)
    selectedData = m_ui->elementComboBox->itemData(curIndex);

  // Clear and repopulate combo
  m_ui->elementComboBox->clear();
  foreach (unsigned char atomicNum, allElements) {
    m_ui->elementComboBox->addItem(QString("%1 (%2)")
                           .arg(Core::Elements::name(atomicNum))
                           .arg(atomicNum), atomicNum);
  }
  m_ui->elementComboBox->insertSeparator(m_ui->elementComboBox->count());
  m_ui->elementComboBox->addItem(tr("Other..."), ELEMENT_SELECTOR_TAG);

  // Reset the element if it still exists
  selectElement(static_cast<unsigned char>(selectedData.isValid()
                                           ? selectedData.toInt() : -1));
}

void TemplateToolWidget::addUserElement(unsigned char element)
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

void TemplateToolWidget::elementSelectedFromTable(int element)
{
  addUserElement(static_cast<unsigned char>(element));
  selectElement(static_cast<unsigned char>(element));
}

void TemplateToolWidget::selectElement(unsigned char element)
{
  int curIndex = element > 0 ? m_ui->elementComboBox->findData(element) : -1;
  if (curIndex >= 0)
    m_ui->elementComboBox->setCurrentIndex(curIndex);
  else {
    addUserElement(element);
    int curIndex = m_ui->elementComboBox->findData(element);
    if (curIndex >= 0)
      m_ui->elementComboBox->setCurrentIndex(curIndex);
    // if we can't find it after adding it, something is very wrong!
  }
}

void TemplateToolWidget::buildElements()
{
  // Common elements that are always shown in the combo box.
  if (m_defaultElements.isEmpty()) {
    m_defaultElements.append(15); // Phosphorus
    m_defaultElements.append(16); // Sulfur
    m_defaultElements.append(22); // Ti
    m_defaultElements.append(23); // V
    m_defaultElements.append(24); // Cr
    m_defaultElements.append(25); // Mn
    m_defaultElements.append(26); // Fe
    m_defaultElements.append(27); // Co
    m_defaultElements.append(28); // Ni
    m_defaultElements.append(29); // Cu
    m_defaultElements.append(30); // Zn
  }

  // User-added elements
  QVariantList userElementsVar =
      QSettings().value("templatetool/userElements").toList();
  foreach (const QVariant &var, userElementsVar)
    m_userElements << static_cast<unsigned char>(var.toUInt());

  updateElementCombo();
}

void TemplateToolWidget::saveElements()
{
  QVariantList atomicNums;
  for (int i = 0; i < m_userElements.size(); ++i)
    atomicNums << QVariant(m_userElements[i]);

  QSettings().setValue("templatetool/userElements", atomicNums);
}

} // namespace QtPlugins
} // namespace Avogadro
