/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "currentpythondialog.h"
#include "ui_currentpythontdialog.h"

#include <QtCore/QSettings>

namespace Avogadro::QtPlugins {

ConfigurePythonDialog::ConfigurePythonDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::ConfigurePythonDialog)
{
  m_ui->setupUi(this);
}

ConfigurePythonDialog::~ConfigurePythonDialog()
{
  delete m_ui;
}

void ConfigurePythonDialog::setOptions(const QStringList& options)
{
  m_ui->environmentCombo->clear();
  m_ui->environmentCombo->addItems(options);

  QSettings settings;
  QString lastUsed = settings.value("ConfigurePython/lastUsed").toString();
  int index = m_ui->environmentCombo->findText(lastUsed);
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);
}

QString ConfigurePythonDialog::option() const
{
  return m_ui->formats->currentText();
}

void ConfigurePythonDialog::setCurrentOption(const QString& option)
{
  int index = m_ui->environmentCombo->findText(format);
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);
}

void ConfigurePythonDialog::accept()
{
  QSettings settings;
  settings.setValue("ConfigurePython/lastUsed", format());
  QDialog::accept();
}

} // namespace Avogadro::QtPlugins
