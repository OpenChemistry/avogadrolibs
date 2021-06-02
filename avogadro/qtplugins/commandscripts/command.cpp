/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "command.h"

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QtWidgets/QAction>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QStringList>
#include <QtCore/QtPlugin>

namespace Avogadro {
namespace QtPlugins {

using Avogadro::QtGui::InterfaceScript;
using Avogadro::QtGui::InterfaceWidget;

Command::Command(QObject* parent_)
  : ExtensionPlugin(parent_), m_molecule(nullptr), m_currentDialog(nullptr),
    m_currentInterface(nullptr), m_currentScript(nullptr), m_progress(nullptr),
    m_outputFormat(nullptr)
{
  refreshScripts();
}

Command::~Command()
{
  qDeleteAll(m_dialogs.values());
  m_dialogs.clear();
}

QList<QAction*> Command::actions() const
{
  return m_actions;
}

QStringList Command::menuPath(QAction* action) const
{
  QString scriptFileName = action->data().toString();
  QStringList path;

  // if we're passed the "Set Python" action
  if (scriptFileName.isEmpty()) {
    path << tr("&Extensions") << tr("Scripts");
    return path;
  }

  // otherwise, we have a script name, so ask it
  InterfaceScript gen(scriptFileName);
  path = gen.menuPath().split('|');
  if (gen.hasErrors()) {
    path << tr("&Extensions") << tr("Scripts");
    qWarning() << "Command: Unable to retrieve menu "
                  "name for: "
               << scriptFileName << "." << gen.errorList().join("\n\n");
    return path;
  }
  return path;
}

void Command::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  m_molecule = mol;

  foreach (InterfaceWidget* dlg, m_dialogs.values())
    dlg->setMolecule(mol);
}

bool Command::readMolecule(QtGui::Molecule& mol)
{
  Io::FileFormat* reader = m_outputFormat->newInstance();
  bool success = reader->readFile(m_outputFileName.toStdString(), mol);
  if (!success) {
    QMessageBox::information(qobject_cast<QWidget*>(parent()), tr("Error"),
                             tr("Error reading output file '%1':\n%2")
                               .arg(m_outputFileName)
                               .arg(QString::fromStdString(reader->error())));
  }

  m_outputFormat = nullptr;
  m_outputFileName.clear();

  return success;
}

void Command::refreshScripts()
{
  updateScripts();
  updateActions();
}

void Command::menuActivated()
{
  QAction* theSender = qobject_cast<QAction*>(sender());
  if (!theSender)
    return;

  QString scriptFileName = theSender->data().toString();
  QWidget* theParent = qobject_cast<QWidget*>(parent());

  if (m_currentDialog) {
    delete m_currentDialog->layout();
    if (m_currentInterface)
      m_currentInterface->hide();
  }

  // check if there are any options before this song-and-dance
  InterfaceWidget* widget = m_dialogs.value(scriptFileName, nullptr);

  if (!widget) {
    widget = new InterfaceWidget(scriptFileName, theParent);
    m_dialogs.insert(scriptFileName, widget);
  }
  widget->setMolecule(m_molecule);
  m_currentInterface = widget; // remember this when we get the run() signal
  if (widget->isEmpty()) {
    run(); // no options, do it immediately
    return;
  }

  m_currentDialog = new QDialog(theParent);
  QString title;
  QtGui::ScriptLoader::queryProgramName(scriptFileName, title);
  m_currentDialog->setWindowTitle(title);

  QVBoxLayout* vbox = new QVBoxLayout();
  widget->show();
  vbox->addWidget(widget);
  QDialogButtonBox* buttonBox =
    new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

  connect(buttonBox, SIGNAL(accepted()), this, SLOT(run()));
  connect(buttonBox, SIGNAL(rejected()), m_currentDialog, SLOT(reject()));
  vbox->addWidget(buttonBox);
  m_currentDialog->setLayout(vbox);
  m_currentDialog->exec();
}

void Command::run()
{
  if (m_currentDialog)
    m_currentDialog->accept();

  if (m_progress)
    m_progress->deleteLater();

  if (m_currentScript) {
    disconnect(m_currentScript, SIGNAL(finished()), this,
                SLOT(processFinished()));
    m_currentScript->deleteLater();
  }

  if (m_currentInterface) {
    QJsonObject options = m_currentInterface->collectOptions();

    // @todo - need a cleaner way to get a script pointer from the widget
    QString scriptFilePath =
      m_currentInterface->interfaceScript().scriptFilePath();
 
    m_currentScript = new InterfaceScript(scriptFilePath, parent());
    connect(m_currentScript, SIGNAL(finished()), this, SLOT(processFinished()));

    // no cancel button - just an indication we're waiting...
    QString title = tr("Processing %1").arg(m_currentScript->displayName());
    m_progress = new QProgressDialog(title, QString(), 0, 0, qobject_cast<QWidget*>(parent()));
    m_progress->setMinimumDuration(1000); // 1 second

    m_currentScript->runCommand(options, m_molecule);
  }
}

void Command::processFinished()
{
  if (m_currentScript == nullptr)
    return;

  if (m_progress) {
    m_progress->close();
    m_progress->deleteLater();
    m_progress = nullptr;
  }

  m_currentScript->processCommand(m_molecule);

  // collect errors
  if (m_currentScript->hasErrors()) {
    qWarning() << m_currentScript->errorList();
  }
}

void Command::configurePython()
{
  // Create objects
  QSettings settings;
  QDialog dlg(qobject_cast<QWidget*>(parent()));
  QLabel* label = new QLabel;
  QVBoxLayout* layout = new QVBoxLayout;
  QtGui::FileBrowseWidget* browser = new QtGui::FileBrowseWidget;
  QDialogButtonBox* buttonBox = new QDialogButtonBox;

  // Configure objects
  // Check for python interpreter in env var
  QString pythonInterp =
    QString::fromLocal8Bit(qgetenv("AVO_PYTHON_INTERPRETER"));
  if (pythonInterp.isEmpty()) {
    // Check settings
    pythonInterp = settings.value("interpreters/python", QString()).toString();
  }
  // Use compile-time default if still not found.
  if (pythonInterp.isEmpty())
    pythonInterp = QString(pythonInterpreterPath);
  browser->setMode(QtGui::FileBrowseWidget::ExecutableFile);
  browser->setFileName(pythonInterp);

  buttonBox->setStandardButtons(QDialogButtonBox::Ok |
                                QDialogButtonBox::Cancel);

  dlg.setWindowTitle(tr("Set path to Python interpreter:"));
  label->setText(
    tr("Select the python interpreter to run external scripts.\n"
       "Avogadro must be restarted for any changes to take effect."));

  // Build layout
  layout->addWidget(label);
  layout->addWidget(browser);
  layout->addWidget(buttonBox);
  dlg.setLayout(layout);

  // Connect
  connect(buttonBox, SIGNAL(accepted()), &dlg, SLOT(accept()));
  connect(buttonBox, SIGNAL(rejected()), &dlg, SLOT(reject()));

  // Show dialog
  QDialog::DialogCode response = static_cast<QDialog::DialogCode>(dlg.exec());
  if (response != QDialog::Accepted)
    return;

  // Handle response
  settings.setValue("interpreters/python", browser->fileName());
}

void Command::updateScripts()
{
  m_commandScripts = QtGui::ScriptLoader::scriptList("commands");
}

void Command::updateActions()
{
  m_actions.clear();

  //  QAction* action = new QAction(tr("Set Python Path..."), this);
  //  connect(action, SIGNAL(triggered()), SLOT(configurePython()));
  //  m_actions << action;

  foreach (const QString& programName, m_commandScripts.uniqueKeys()) {
    QStringList scripts = m_commandScripts.values(programName);
    // Include the full path if there are multiple generators with the same
    // name.
    if (scripts.size() == 1) {
      addAction(programName, scripts.first());
    } else {
      foreach (const QString& filePath, scripts) {
        addAction(QString("%1 (%2)").arg(programName, filePath), filePath);
      }
    }
  }
}

void Command::addAction(const QString& label, const QString& scriptFilePath)
{
  QAction* action = new QAction(label, this);
  action->setData(scriptFilePath);
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
}

} // namespace QtPlugins
} // namespace Avogadro
