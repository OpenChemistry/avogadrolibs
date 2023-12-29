/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configurepythondialog.h"
#include "ui_configurepythondialog.h"

#include <QtCore/QSettings>

namespace Avogadro::QtPlugins {

ConfigurePythonDialog::ConfigurePythonDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::ConfigurePythonDialog)
{
  m_ui->setupUi(this);
  m_ui->browseWidget->hide();

  connect(m_ui->environmentCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(optionChanged(int)));
}

ConfigurePythonDialog::~ConfigurePythonDialog()
{
  delete m_ui;
}

void ConfigurePythonDialog::setOptions(const QStringList& options)
{
  m_ui->environmentCombo->clear();
  m_ui->environmentCombo->addItems(options);
  m_ui->environmentCombo->addItem("Other…");

  QSettings settings;
  QString lastUsed = settings.value("ConfigurePython/lastUsed").toString();
  int index = m_ui->environmentCombo->findText(lastUsed);
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);
}

void ConfigurePythonDialog::optionChanged(int index)
{
  if (index == m_ui->environmentCombo->count() - 1) {
    // "Other…" selected
    m_ui->browseWidget->setEnabled(true);
    m_ui->browseWidget->show();
  } else {
    m_ui->browseWidget->setEnabled(false);
    m_ui->browseWidget->hide();
  }
}

QString ConfigurePythonDialog::currentOption() const
{
  if (m_ui->environmentCombo->currentIndex() ==
      m_ui->environmentCombo->count() - 1)
    return m_ui->browseWidget->fileName();

  return m_ui->environmentCombo->currentText();
}

void ConfigurePythonDialog::setCurrentOption(const QString& option)
{
  int index = m_ui->environmentCombo->findText(option);
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);
}

void ConfigurePythonDialog::accept()
{
  QSettings settings;
  settings.setValue("ConfigurePython/lastUsed", currentOption());
  QDialog::accept();
}

} // namespace Avogadro::QtPlugins
