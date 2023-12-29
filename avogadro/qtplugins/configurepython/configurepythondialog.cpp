/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configurepythondialog.h"
#include "ui_configurepythondialog.h"

#include <QtCore/QProcess>

namespace Avogadro::QtPlugins {

ConfigurePythonDialog::ConfigurePythonDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::ConfigurePythonDialog)
{
  m_ui->setupUi(this);
  m_ui->browseWidget->hide();

  connect(m_ui->environmentCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(optionChanged(int)));

  connect(m_ui->buttonBox, SIGNAL(accepted()), SLOT(accept()));
  connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(reject()));
}

ConfigurePythonDialog::~ConfigurePythonDialog()
{
  delete m_ui;
}

void ConfigurePythonDialog::setOptions(const QStringList& options)
{
  m_ui->environmentCombo->clear();

  // get the Python version from each interpreter
  QStringList versions, arguments;
  QProcess process;
  arguments << "-V";
  foreach (const QString& option, options) {
    process.start(option, arguments);
    if (process.waitForFinished()) {
      QString output = process.readAllStandardOutput();
      if (output.startsWith("Python")) {
        versions << output.split(" ").at(1);
      } else {
        versions << tr("Unknown");
      }
    } else {
      versions << tr("Unknown");
    }
  }

  for (int i = 0; i < options.size(); ++i) {
    m_ui->environmentCombo->addItem(
      QString("%1 (%2)").arg(options.at(i)).arg(versions.at(i)));
  }

  m_ui->environmentCombo->addItem("Other…");
  m_ui->browseWidget->hide();
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

  QString path = m_ui->environmentCombo->currentText();
  // remove the Python version to get the path
  int index = path.indexOf(" (");
  if (index >= 0)
    return path.left(index);

  return path;
}

void ConfigurePythonDialog::reject()
{
  QDialog::reject();

  emit rejected();
}

void ConfigurePythonDialog::accept()
{
  QDialog::accept();

  emit accepted();
}

void ConfigurePythonDialog::setCurrentOption(const QString& option)
{
  int index = m_ui->environmentCombo->findText(option);
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);
}

} // namespace Avogadro::QtPlugins
