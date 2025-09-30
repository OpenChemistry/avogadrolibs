/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "apbsoutputdialog.h"

#include "ui_apbsoutputdialog.h"

namespace Avogadro::QtPlugins {

ApbsOutputDialog::ApbsOutputDialog(QWidget* parent_)
  : QDialog(parent_), m_ui(new Ui::ApbsOutputDialog)
{
  m_ui->setupUi(this);
}

ApbsOutputDialog::~ApbsOutputDialog() {}

bool ApbsOutputDialog::loadStructureFile() const
{
  return m_ui->loadStructureCheckBox->isChecked();
}

bool ApbsOutputDialog::loadCubeFile() const
{
  return m_ui->loadCubeCheckBox->isChecked();
}
} // namespace Avogadro::QtPlugins
