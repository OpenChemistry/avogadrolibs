/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "command.h"

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/interfacescript.h>
#include <avogadro/qtgui/interfacewidget.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/packagemanager.h>
#include <avogadro/qtgui/pythonscript.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <QAction>
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

namespace Avogadro::QtPlugins {

using Avogadro::QtGui::InterfaceScript;
using Avogadro::QtGui::InterfaceWidget;

Command::Command(QObject* parent_)
  : ExtensionPlugin(parent_), m_molecule(nullptr), m_currentDialog(nullptr),
    m_currentInterface(nullptr), m_currentScript(nullptr), m_progress(nullptr),
    m_outputFormat(nullptr)
{
  refreshScripts();

  // Connect to PackageManager for pyproject.toml-based packages
  auto* pm = QtGui::PackageManager::instance();
  connect(pm, &QtGui::PackageManager::featureRegistered, this,
          &Command::registerFeature);
  connect(pm, &QtGui::PackageManager::featureRemoved, this,
          &Command::unregisterFeature);
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
  // Package-based actions carry their menu path in a property
  QVariant pkgMenuPath = action->property("packageMenuPath");
  if (pkgMenuPath.isValid())
    return pkgMenuPath.toStringList();

  QString scriptFileName = action->data().toString();
  QStringList path;

  // if we have an empty script name, default to Extensions > Scripts
  if (scriptFileName.isEmpty()) {
    path << tr("&Extensions") << tr("Scripts");
    return path;
  }

  // cache the menu paths
  QSettings settings;
  QFileInfo info(scriptFileName); // check if the script matches the hash
  QString hash =
    settings.value("scripts/" + scriptFileName + "/hash").toString();
  if (hash == QString::number(info.size()) + info.lastModified().toString()) {
    path = settings.value("scripts/" + scriptFileName + "/menu").toStringList();
    if (!path.isEmpty())
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

  // look for {number} in the last part of the path
  // (this is a priority integer)
  QString lastPart = path.takeLast();
  int priority = 0;
  int braceIndex = lastPart.indexOf('{');
  int endBraceIndex = lastPart.indexOf('}');
  if (braceIndex >= 0 && endBraceIndex >= 0 && endBraceIndex > braceIndex) {
    bool ok = false;
    size_t len = endBraceIndex - braceIndex - 1;
    priority = lastPart.mid(braceIndex + 1, len).toInt(&ok);
    if (ok) {
      lastPart = lastPart.left(braceIndex);
    }
  }
  // add it back to the path
  path << lastPart;

  // cache the path
  settings.setValue("scripts/" + scriptFileName + "/menu", path);

  if (priority != 0) {
    action->setProperty("menu priority", priority);
  }

  // try to translate each part of the path
  // not ideal, but most menus should already be in the translation file
  QStringList translatedPath;
  foreach (QString part, path)
    translatedPath << tr(part.toUtf8());

  return translatedPath;
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
  auto* theSender = qobject_cast<QAction*>(sender());
  if (!theSender)
    return;

  QWidget* theParent = qobject_cast<QWidget*>(parent());

  if (m_currentDialog) {
    delete m_currentDialog->layout();
    if (m_currentInterface)
      m_currentInterface->hide();
  }

  bool isPackage = theSender->property("packageMode").toBool();
  QString key; // dialog cache key
  InterfaceWidget* widget = nullptr;

  if (isPackage) {
    QString pkgDir = theSender->property("packageDir").toString();
    QString pkgCmd = theSender->property("packageCommand").toString();
    QString pkgId = theSender->property("packageIdentifier").toString();
    key = QStringLiteral("pkg:") + pkgId;

    widget = m_dialogs.value(key, nullptr);
    if (!widget) {
      widget = new InterfaceWidget(QString(), theParent);
      widget->interfaceScript().interpreter().setPackageInfo(pkgDir, pkgCmd,
                                                             pkgId);
      widget->reloadOptions();
      m_dialogs.insert(key, widget);
    }
  } else {
    key = theSender->data().toString();
    widget = m_dialogs.value(key, nullptr);
    if (!widget) {
      widget = new InterfaceWidget(key, theParent);
      m_dialogs.insert(key, widget);
    }
  }

  widget->setMolecule(m_molecule);
  m_currentInterface = widget;
  if (widget->isEmpty()) {
    run(); // no options, do it immediately
    return;
  }

  m_currentDialog = new QDialog(theParent);
  m_currentDialog->setWindowTitle(theSender->text());

  auto* vbox = new QVBoxLayout();
  widget->show();
  vbox->addWidget(widget);
  auto* buttonBox =
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
    const auto& iface = m_currentInterface->interfaceScript();

    // Create a new InterfaceScript with the same configuration
    m_currentScript = new InterfaceScript(parent());
    const auto& interp = iface.interpreter();
    if (interp.isPackageMode()) {
      m_currentScript->interpreter().setPackageInfo(interp.packageDir(),
                                                    interp.packageCommand(),
                                                    interp.packageIdentifier());
    } else {
      m_currentScript->setScriptFilePath(iface.scriptFilePath());
    }
    connect(m_currentScript, SIGNAL(finished()), this, SLOT(processFinished()));

    // no cancel button - just an indication we're waiting...
    QString title = tr("Processing %1").arg(iface.displayName());
    m_progress = new QProgressDialog(title, QString(), 0, 0,
                                     qobject_cast<QWidget*>(parent()));
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
  auto* label = new QLabel;
  auto* layout = new QVBoxLayout;
  auto* browser = new QtGui::FileBrowseWidget;
  auto* buttonBox = new QDialogButtonBox;

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
  auto response = static_cast<QDialog::DialogCode>(dlg.exec());
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

  //  QAction* action = new QAction(tr("Set Python Path…"), this);
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
  auto* action = new QAction(tr(label.toUtf8()), this);
  action->setData(scriptFilePath);
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
}

void Command::registerFeature(const QString& type, const QString& packageDir,
                              const QString& command, const QString& identifier,
                              const QVariantMap& metadata)
{
  if (type != QLatin1String("menu-commands"))
    return;

  // Extract label from metadata: path.entry.label
  QVariantMap pathMap = metadata.value("path").toMap();
  QVariantMap entryMap = pathMap.value("entry").toMap();
  QString label = entryMap.value("label").toString();
  if (label.isEmpty())
    label = identifier;

  // Build menu path from metadata: path.menu, path.submenu.menu, ...
  QStringList menuPathList;
  QString topMenu = pathMap.value("menu").toString();
  if (!topMenu.isEmpty())
    menuPathList << topMenu;

  // Check for submenu
  QString submenu = pathMap.value("submenu").toMap().value("menu").toString();
  if (!submenu.isEmpty())
    menuPathList << submenu;

  // If no menu path specified, default to Extensions > Scripts
  if (menuPathList.isEmpty())
    menuPathList << tr("&Extensions") << tr("Scripts");

  // Extract priority
  int priority = entryMap.value("priority", 0).toInt();

  // Create the action
  auto* action = new QAction(label, this);
  action->setProperty("packageMode", true);
  action->setProperty("packageDir", packageDir);
  action->setProperty("packageCommand", command);
  action->setProperty("packageIdentifier", identifier);
  action->setProperty("packageMenuPath", menuPathList);
  action->setEnabled(true);

  if (priority != 0)
    action->setProperty("menu priority", priority);

  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
  m_packageActions.insert(identifier, action);
}

void Command::unregisterFeature(const QString& type, const QString& identifier)
{
  if (type != QLatin1String("menu-commands"))
    return;

  const QList<QAction*> actions = m_packageActions.values(identifier);
  if (actions.isEmpty())
    return;

  m_packageActions.remove(identifier);

  const QString key = QStringLiteral("pkg:") + identifier;
  InterfaceWidget* widget = m_dialogs.take(key);
  if (widget) {
    if (widget == m_currentInterface) {
      if (m_currentDialog) {
        m_currentDialog->reject();
        m_currentDialog->deleteLater();
        m_currentDialog = nullptr;
      }
      m_currentInterface = nullptr;
    }
    delete widget;
  }

  for (QAction* action : actions) {
    m_actions.removeAll(action);
    action->deleteLater();
  }
}

} // namespace Avogadro::QtPlugins
