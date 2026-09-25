/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energyunitsdialog.h"

#include <avogadro/core/molecule.h>

#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro::QtGui {

namespace {

// The unit itself rides along in the item data, so the combo's order and the
// enum's need not agree.
void fillUnitCombo(QComboBox* combo, EnergyUnits::Unit current)
{
  for (EnergyUnits::Unit unit : EnergyUnits::units()) {
    combo->addItem(EnergyUnits::symbol(unit), static_cast<int>(unit));
    if (unit == current)
      combo->setCurrentIndex(combo->count() - 1);
  }
}

EnergyUnits::Unit unitFromCombo(const QComboBox* combo,
                                EnergyUnits::Unit fallback)
{
  bool ok = false;
  const int value = combo->currentData().toInt(&ok);
  if (!ok)
    return fallback;

  for (EnergyUnits::Unit unit : EnergyUnits::units()) {
    if (static_cast<int>(unit) == value)
      return unit;
  }
  return fallback;
}

} // namespace

EnergyUnitsDialog::EnergyUnitsDialog(QWidget* parent,
                                     const Core::Molecule* molecule)
  : QDialog(parent), m_sourceCombo(new QComboBox(this)),
    m_displayCombo(new QComboBox(this)),
    m_sourceDeclared(molecule != nullptr &&
                     EnergyUnits::declaresUnit(*molecule))
{
  setWindowTitle(tr("Convert Energy Units"));

  auto* units = EnergyUnits::instance();
  fillUnitCombo(m_sourceCombo, molecule != nullptr
                                 ? units->sourceUnit(*molecule)
                                 : units->sourceUnit());
  fillUnitCombo(m_displayCombo, units->displayUnit());
  // Nothing to choose where the file already said: show it, and leave open
  // only the question that still is.
  m_sourceCombo->setEnabled(!m_sourceDeclared);

  auto* mainLayout = new QVBoxLayout(this);

  auto* explanation = new QLabel(
    m_sourceDeclared
      ? tr("This file records the units its energies are in.")
      : tr("Energies are read in the units the file used, which may not be "
           "recorded."),
    this);
  explanation->setWordWrap(true);
  mainLayout->addWidget(explanation);

  // Reads as a sentence: "Convert energies from Hartree to kcal/mol".
  auto* unitsLayout = new QHBoxLayout();
  auto* fromLabel = new QLabel(tr("Convert energies from:"), this);
  fromLabel->setBuddy(m_sourceCombo);
  auto* toLabel = new QLabel(tr("to"), this);
  toLabel->setBuddy(m_displayCombo);

  unitsLayout->addWidget(fromLabel);
  unitsLayout->addWidget(m_sourceCombo);
  unitsLayout->addWidget(toLabel);
  unitsLayout->addWidget(m_displayCombo);
  unitsLayout->addStretch();
  mainLayout->addLayout(unitsLayout);

  auto* buttons =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this,
          &EnergyUnitsDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this,
          &EnergyUnitsDialog::reject);
  mainLayout->addWidget(buttons);
}

EnergyUnitsDialog::~EnergyUnitsDialog() = default;

void EnergyUnitsDialog::accept()
{
  auto* units = EnergyUnits::instance();
  // Both at once, so that changing the pair wakes everything showing an
  // energy once rather than twice. A source the file declared is left alone:
  // it belongs to this molecule, and is not the user's answer for every file
  // they open next.
  units->setUnits(m_sourceDeclared
                    ? units->sourceUnit()
                    : unitFromCombo(m_sourceCombo, units->sourceUnit()),
                  unitFromCombo(m_displayCombo, units->displayUnit()));

  QDialog::accept();
}

bool EnergyUnitsDialog::getUnits(QWidget* parent,
                                 const Core::Molecule* molecule)
{
  EnergyUnitsDialog dialog(parent, molecule);
  return dialog.exec() == QDialog::Accepted;
}

} // namespace Avogadro::QtGui
