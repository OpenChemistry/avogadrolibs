/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "inputgeneratordialog.h"
#include "ui_inputgeneratordialog.h"

#include "inputgeneratorwidget.h"

namespace Avogadro {
namespace MoleQueue {

using QtGui::Molecule;

InputGeneratorDialog::InputGeneratorDialog(QWidget* parent_)
  : QDialog(parent_), ui(new Ui::InputGeneratorDialog)
{
  ui->setupUi(this);
  connect(ui->widget, SIGNAL(closeClicked()), SLOT(accept()));
}

InputGeneratorDialog::InputGeneratorDialog(const QString& scriptFileName,
                                           QWidget* parent_)
  : QDialog(parent_), ui(new Ui::InputGeneratorDialog)
{
  ui->setupUi(this);
  connect(ui->widget, SIGNAL(closeClicked()), SLOT(accept()));
  this->setInputGeneratorScript(scriptFileName);
}

InputGeneratorDialog::~InputGeneratorDialog()
{
  delete ui;
}

void InputGeneratorDialog::setInputGeneratorScript(const QString& scriptFile)
{
  ui->widget->setInputGeneratorScript(scriptFile);
  QString displayName(ui->widget->inputGenerator().displayName());
  if (ui->widget->inputGenerator().hasErrors())
    setWindowTitle(tr("Input Generator (error)").arg(displayName));
  else
    setWindowTitle(tr("%1 Input Generator").arg(displayName));
}

InputGeneratorWidget& InputGeneratorDialog::widget()
{
  return *ui->widget;
}

const InputGeneratorWidget& InputGeneratorDialog::widget() const
{
  return *ui->widget;
}

bool InputGeneratorDialog::configureBatchJob(BatchJob& batch)
{
  ui->widget->setBatchMode(true);
  DialogCode reply = static_cast<DialogCode>(exec());
  if (reply != Accepted)
    return false;

  return ui->widget->configureBatchJob(batch);
}

void InputGeneratorDialog::setMolecule(Molecule* mol)
{
  ui->widget->setMolecule(mol);
}

} // namespace MoleQueue
} // namespace Avogadro
