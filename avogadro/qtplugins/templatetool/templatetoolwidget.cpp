/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "templatetoolwidget.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/periodictableview.h>
#include <qcombobox.h>
#include <qglobal.h>
#include <qicon.h>
#include <qmetatype.h>
#include <qsettings.h>
#include <qtoolbutton.h>
#include <qvariant.h>
#include <algorithm>

#include "ui_templatetoolwidget.h"

namespace {
// The ItemData of the "Other" entry in the combo box
const int ELEMENT_SELECTOR_TAG = 255;
} // namespace

namespace Avogadro {
namespace QtPlugins {

TemplateToolWidget::TemplateToolWidget(QWidget* parent_)
  : QWidget(parent_), m_ui(new Ui::TemplateToolWidget), m_elementSelector(NULL),
    m_currentElement(26)
{
  m_ui->setupUi(this);

  buildElements();

  connect(m_ui->elementComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(elementChanged(int)));

  connect(m_ui->coordinationComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(coordinationChanged(int)));

  connect(m_ui->typeComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(typeChanged(int)));

  connect(m_ui->ligandComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(ligandChanged(int)));

  // Show iron at startup.
  selectElement(26);
  // default coordination = octahedral
  m_ui->centerPreview->setIcon(QIcon(":/icons/centers/6-oct.png"));

  // In the same order of the coordinationComboBox
  // append ".png" for the icon and ".cjson" for the template
  m_centers << "1-lin"
            << "2-lin"
            << "3-tpl"
            << "4-tet"
            << "4-sqp"
            << "5-tbp"
            << "5-spy"
            << "6-oct"
            << "6-tpr"
            << "7-pbp"
            << "8-sqa";

  typeChanged(0);
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

signed char TemplateToolWidget::formalCharge() const
{
  return m_ui->chargeComboBox->currentIndex() - 0;
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

unsigned char TemplateToolWidget::ligand() const
{
  return static_cast<unsigned char>(m_ui->ligandComboBox->currentIndex());
}

QString TemplateToolWidget::ligandString() const
{
  return m_ligands.at(m_ui->ligandComboBox->currentIndex());
}

void TemplateToolWidget::coordinationChanged(int index)
{
  if (index < 0 || index > m_ui->coordinationComboBox->count())
    return;

  // get the icon name
  QString iconName = m_centers[index];
  m_ui->centerPreview->setIcon(QIcon(":/icons/centers/" + iconName + ".png"));
}

void TemplateToolWidget::ligandChanged(int index)
{
  if (index < 0 || index > m_ui->ligandComboBox->count())
    return;

  // get the icon name
  QString iconName = m_ligands[index];
  m_ui->ligandPreview->setIcon(QIcon(":/icons/ligands/" + iconName + ".png"));
}

void TemplateToolWidget::typeChanged(int index)
{
  m_selectedUIDs.clear();
  m_ui->ligandComboBox->clear();
  m_ligands = QStringList();
  QStringList ligandNames;
  switch (index) {
    case 0: // Monodentate
      ligandNames << "ammine"
                  << "aqua"
                  << "carbonyl"
                  << "cyano"
                  << "phosphine"
                  << "thiol";
      m_ligands << "1-ammine"
                << "1-aqua"
                << "1-carbonyl"
                << "1-cyano"
                << "1-phosphine"
                << "1-thiol";
      m_denticity = 1;
      break;
    case 1: // Bidentate
      ligandNames << "acetylacetonate"
                  << "bipyridine"
                  << "ethylenediamine";
      m_ligands << "2-acetylacetonate"
                << "2-bipyridine"
                << "2-ethylenediamine";
      m_denticity = 2;
      break;
    case 2: // Tridentate
      ligandNames << "terpyridine";
      m_ligands << "3-terpyridine";
      m_denticity = 3;
      break;
    case 3: // Tetradentate
      ligandNames << "phthalocyanine"
                  << "porphin"
                  << "salen";
      m_ligands << "4-phthalocyanine"
                << "4-porphin"
                << "4-salen";
      m_denticity = 4;
      break;
    case 4: // Hexadentate
      ligandNames << "edta";
      m_ligands << "6-edta";
      m_denticity = 6;
      break;
    case 5: // Haptic
      ligandNames << "η2-ethylene"
                  << "η5-cyclopentyl"
                  << "η6-benzene";
      m_ligands << "eta2-ethylene"
                << "eta5-cyclopentyl"
                << "eta6-benzene";
      m_denticity = 1;
      break;
    case 6: // Functional Groups
      ligandNames << "amide"
                  << "carboxylate"
                  << "ester"
                  << "nitro"
                  << "phenyl"
                  << "sulfonate";
      m_ligands = ligandNames;
      m_denticity = 1;
      break;
  }
  m_ui->ligandComboBox->addItems(ligandNames);
}

void TemplateToolWidget::elementChanged(int index)
{
  QVariant itemData = m_ui->elementComboBox->itemData(index);
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

void TemplateToolWidget::updateElementCombo()
{
  // Build set of all elements:
  QList<unsigned char> allElements;
  allElements << m_defaultElements;
  allElements << m_userElements;
  std::sort(allElements.begin(), allElements.end());

  // Cache selected atomic number for later
  QVariant selectedData;
  int curIndex = m_ui->elementComboBox->currentIndex();
  if (curIndex >= 0)
    selectedData = m_ui->elementComboBox->itemData(curIndex);

  // Clear and repopulate combo
  m_ui->elementComboBox->clear();
  foreach (unsigned char atomicNum, allElements) {
    m_ui->elementComboBox->addItem(
      QString("%1 (%2)").arg(Core::Elements::name(atomicNum)).arg(atomicNum),
      atomicNum);
  }
  m_ui->elementComboBox->insertSeparator(m_ui->elementComboBox->count());
  m_ui->elementComboBox->addItem(tr("Other..."), ELEMENT_SELECTOR_TAG);

  // Reset the element if it still exists
  selectElement(static_cast<unsigned char>(
    selectedData.isValid() ? selectedData.toInt() : -1));
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
    curIndex = m_ui->elementComboBox->findData(element);
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
  foreach (const QVariant& var, userElementsVar)
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

int TemplateToolWidget::denticity() const
{
  return m_denticity;
}

std::vector<size_t>& TemplateToolWidget::selectedUIDs()
{
  return m_selectedUIDs;
}

} // namespace QtPlugins
} // namespace Avogadro
