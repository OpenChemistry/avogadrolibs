/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "condadialog.h"
#include "ui_condadialog.h"

namespace Avogadro::QtPlugins {

CondaDialog::CondaDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::CondaDialog)
{
  m_ui->setupUi(this);
}

CondaDialog::~CondaDialog()
{
  delete m_ui;
}

QString CondaDialog::environmentName() const
{
  return m_ui->environmentName->text();
}

} // namespace Avogadro::QtPlugins
