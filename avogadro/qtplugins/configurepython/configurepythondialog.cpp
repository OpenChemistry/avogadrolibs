/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "configurepythondialog.h"
#include "condadialog.h"

#include "ui_configurepythondialog.h"

#include <avogadro/qtgui/utilities.h>

#include <QDebug>
#include <QFileInfo>
#include <QtCore/QProcess>
#include <QtCore/QSettings>

using Avogadro::QtGui::Utilities::findExecutablePaths;

namespace Avogadro::QtPlugins {

ConfigurePythonDialog::ConfigurePythonDialog(QWidget* aParent)
  : QDialog(aParent), m_ui(new Ui::ConfigurePythonDialog), m_condaUi(nullptr)
{
  m_ui->setupUi(this);
  m_ui->browseWidget->hide();

  connect(m_ui->environmentCombo, SIGNAL(currentIndexChanged(int)),
          SLOT(optionChanged(int)));

  connect(m_ui->buttonBox, SIGNAL(accepted()), SLOT(accept()));
  connect(m_ui->buttonBox, SIGNAL(rejected()), SLOT(reject()));

  // look for conda environments
  QProcess condaProcess;
  QSettings settings;
  QString condaPath =
    settings.value("interpreters/condaPath", "conda").toString();
  // check if conda is executable
  if (!QFileInfo(condaPath).isExecutable()) {
    // see if we can find any related executables in the path
    QStringList names;
    names << "micromamba"
          << "mamba"
          << "conda";
#ifdef Q_OS_WIN
    names << "micromamba.exe"
          << "mamba.exe"
          << "conda.exe";
#endif
    QStringList paths = findExecutablePaths(names);
    if (!paths.isEmpty()) {
      condaPath = paths.first();
    } else
      return; // nothing more to do
  }

  // set the path to conda
  settings.setValue("interpreters/condaPath", condaPath);

  // get the list of environments
  condaProcess.start(condaPath, QStringList() << "env"
                                              << "list");
  if (condaProcess.waitForFinished()) {
    QString output = condaProcess.readAllStandardOutput();
    QStringList lines = output.split("\n");
    foreach (const QString& line, lines) {
      if (line.startsWith("#"))
        continue;

      QStringList parts = line.split(" ");
      if (parts.size() > 1)
        m_condaEnvironments << parts.at(0);
    }
  }
  if (m_condaEnvironments.size() < 2) {
    // no environment or only the base found
    setupCondaEnvironment();
  }
}

ConfigurePythonDialog::~ConfigurePythonDialog()
{
  delete m_ui;
}

void ConfigurePythonDialog::setupCondaEnvironment()
{
  // suggest the user create a new environment through a dialog
  if (m_condaUi == nullptr) {
    m_condaUi = new CondaDialog(qobject_cast<QWidget*>(parent()));
  }
  int choice = m_condaUi->exec();
  if (choice == QDialog::Rejected)
    return;

  QString newEnvironment = m_condaUi->environmentName();
  if (newEnvironment.isEmpty())
    return;

  // create the environment
  QProcess condaProcess;
  QSettings settings;
  QString condaPath =
    settings.value("interpreters/condaPath", "conda").toString();
  // check if conda is executable
  if (!QFileInfo(condaPath).isExecutable()) {
    // see if we can find any related executables in the path
    QStringList names;
    names << "micromamba"
          << "mamba"
          << "conda";
#ifdef Q_OS_WIN
    names << "micromamba.exe"
          << "mamba.exe"
          << "conda.exe";
#endif
    QStringList paths = findExecutablePaths(names);
    if (!paths.isEmpty()) {
      condaPath = paths.first();
    } else
      return; // nothing more to do
  }

  QStringList arguments;
  arguments << "create"
            << "-n" << newEnvironment << "--clone"
            << "base";
  condaProcess.start(condaPath, arguments);
  if (condaProcess.waitForFinished()) {
    QString output = condaProcess.readAllStandardOutput();
    if (output.contains("done")) {
      // environment created
      m_condaEnvironments << newEnvironment;
      settings.setValue("interpreters/condaEnvironment", newEnvironment);
    }
  }
}

QString ConfigurePythonDialog::condaPath() const
{
  QSettings settings;
  QString path = settings.value("interpreters/condaPath").toString();
  return path;
}

QString ConfigurePythonDialog::condaEnvironment() const
{
  QSettings settings;
  QString environment =
    settings.value("interpreters/condaEnvironment").toString();
  return environment;
}

void ConfigurePythonDialog::setOptions(const QStringList& options)
{
  m_ui->environmentCombo->clear();

  // check the current choice from QSettings
  QSettings settings;
  QString currentInterpreter =
    settings.value("interpreters/python", QString()).toString();
  QString currentConda =
    settings.value("interpreters/condaEnvironment", QString()).toString();
  int index = -1;

  // add all conda environments
  foreach (const QString& environment, m_condaEnvironments) {
    if (environment.isEmpty())
      continue; // shouldn't happen, but just in case

    m_ui->environmentCombo->addItem(QString("%1 (conda)").arg(environment));
    if (environment == currentConda)
      index = m_ui->environmentCombo->count() - 1;
  }

  // get the Python version from each interpreter
  QStringList versions, arguments;
  QProcess process;
  arguments << "-V";
  foreach (const QString& option, options) {
    process.start(option, arguments);
    if (process.waitForFinished()) {
      QString output = process.readAllStandardOutput();
      if (output.startsWith("Python")) {
        versions << output.split(" ").at(1).simplified();
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
    // if the conda environment isn't the current, check the python interpreter
    if (options.at(i) == currentInterpreter && index == -1)
      index = m_ui->environmentCombo->count() - 1;
  }

  m_ui->environmentCombo->addItem(tr("Other…"));
  // set the current choice
  if (index >= 0)
    m_ui->environmentCombo->setCurrentIndex(index);

  m_ui->browseWidget->hide();
}

void ConfigurePythonDialog::optionChanged(int index)
{
  // if there's only one choice, check if it's "Other…"
  if ((index == m_ui->environmentCombo->count() - 1) ||
      m_ui->environmentCombo->currentText() == tr("Other…")) {
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
  // check if this is a conda choice
  int index = path.indexOf(" (conda)");
  if (index >= 0) {
    // get the environment name
    QString environment = path.left(index);
    QSettings settings;
    settings.setValue("interpreters/condaEnvironment", environment);

    // activate the environment and get the path to the python interpreter
    QProcess condaProcess;
    QString condaPath =
      settings.value("interpreters/condaPath", "conda").toString();
    // check if conda is executable
    if (!QFileInfo(condaPath).isExecutable())
      return QString();
    condaProcess.start(condaPath, QStringList()
                                    << "run"
                                    << "-n" << environment << "which"
                                    << "python");
    if (condaProcess.waitForFinished()) {
      QString output = condaProcess.readAllStandardOutput();
      qDebug() << " output: " << output << "\n";
      if (output.contains("python")) {
        // remove the newline
        output.remove("\n");
        return output;
      }
    }
  }

  // remove the Python version to get the path
  index = path.indexOf(" (");
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
