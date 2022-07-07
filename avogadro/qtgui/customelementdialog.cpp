/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "customelementdialog.h"
#include "ui_customelementdialog.h"

#include "elementtranslator.h"
#include "molecule.h"

#include <avogadro/core/elements.h>

#include <QtWidgets/QComboBox>

#include <set>

using Avogadro::Core::Elements;

namespace Avogadro::QtGui {

CustomElementDialog::CustomElementDialog(Molecule& mol, QWidget* p)
  : QDialog(p), m_ui(new Ui::CustomElementDialog), m_molecule(mol)
{
  m_ui->setupUi(this);
  prepareElements();
  prepareForm();
}

CustomElementDialog::~CustomElementDialog()
{
  delete m_ui;
}

void CustomElementDialog::resolve(QWidget* p, Molecule& mol)
{
  CustomElementDialog dlg(mol, p);
  int reply = dlg.exec();
  if (static_cast<DialogCode>(reply) == Accepted)
    dlg.apply();
}

namespace {
struct RemapAtomicNumbers
{
  typedef std::map<unsigned char, unsigned char> MapType;
  const MapType& map;

  RemapAtomicNumbers(const MapType& m) : map(m) {}
  RemapAtomicNumbers(const RemapAtomicNumbers& o) : map(o.map) {}

  unsigned char operator()(unsigned char old) const
  {
    if (Core::isCustomElement(old)) {
      auto it = map.find(old);
      return it == map.end() ? old : it->second;
    }
    return old;
  }
};
} // namespace

void CustomElementDialog::apply()
{
  RemapAtomicNumbers::MapType oldToNew;
  Molecule::CustomElementMap newMap;
  const Molecule::CustomElementMap& oldMap = m_molecule.customElementMap();
  unsigned char newIdGenerator = CustomElementMin;
  foreach (QComboBox* combo, findChildren<QComboBox*>()) {
    unsigned char oldId =
      static_cast<unsigned char>(combo->property("id").toUInt());

    int currentIndex = combo->currentIndex();

    if (currentIndex == 0) {
      // Reuse old name:
      unsigned char newId = newIdGenerator++;
      auto it = oldMap.find(oldId);
      newMap.insert(std::make_pair(newId, it->second));
      oldToNew.insert(std::make_pair(oldId, newId));
    } else {
      // New element assigned:
      auto newId = static_cast<unsigned char>(currentIndex);
      oldToNew.insert(std::make_pair(oldId, newId));
    }
  }

  if (newMap.size() != oldMap.size()) {
    Core::Array<unsigned char> atomicNumbers = m_molecule.atomicNumbers();
    std::transform(atomicNumbers.begin(), atomicNumbers.end(),
                   atomicNumbers.begin(), RemapAtomicNumbers(oldToNew));
    m_molecule.setAtomicNumbers(atomicNumbers);
    m_molecule.setCustomElementMap(newMap);
    m_molecule.emitChanged(Molecule::Atoms | Molecule::Modified);
  }
}

void CustomElementDialog::prepareElements()
{
  int maxNumber = ElementTranslator::numberOfElements();
  m_elements.reserve(maxNumber);
  for (int i = 1; i <= maxNumber; ++i)
    m_elements.append(ElementTranslator::name(i));
}

namespace {
struct CustomElementFilter
{
  std::set<unsigned char> customElements;
  void operator()(unsigned char atomicNumber)
  {
    if (Core::isCustomElement(atomicNumber))
      customElements.insert(atomicNumber);
  }

  operator std::set<unsigned char>() const { return customElements; }
};
} // namespace

void CustomElementDialog::prepareForm()
{
  const Molecule::CustomElementMap& map = m_molecule.customElementMap();
  const Core::Array<unsigned char>& atomicNumbers = m_molecule.atomicNumbers();

  std::set<unsigned char> customElements = std::for_each(
    atomicNumbers.begin(), atomicNumbers.end(), CustomElementFilter());

  Molecule::CustomElementMap::const_iterator match;
  for (unsigned char customElement : customElements) {
    if ((match = map.find(customElement)) != map.end())
      addRow(customElement, QString::fromStdString(match->second));
    else
      addRow(customElement, QString::fromStdString(Elements::name(customElement)));
  }
}

void CustomElementDialog::addRow(unsigned char elementId, const QString& name)
{
  auto* combo = new QComboBox(this);
  combo->setProperty("id", static_cast<unsigned int>(elementId));
  combo->addItem(name);
  combo->addItems(m_elements);

  unsigned int atomicNumber = Elements::guessAtomicNumber(name.toStdString());
  if (atomicNumber != InvalidElement)
    combo->setCurrentIndex(static_cast<int>(atomicNumber));
  else
    combo->setCurrentIndex(0);

  m_ui->form->addRow(name + ":", combo);
}

} // namespace Avogadro
