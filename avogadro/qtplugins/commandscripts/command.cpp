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
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
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

void Command::refreshScripts() {}

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
    key = QtGui::PackageManager::packageFeatureKey(pkgDir, pkgCmd, pkgId);

    widget = m_dialogs.value(key, nullptr);
    if (!widget) {
      widget = new InterfaceWidget(QString(), theParent);
      widget->interfaceScript().interpreter().setPackageInfo(pkgDir, pkgCmd,
                                                             pkgId);

      // Build options from pyproject.toml metadata; never call --print-options
      // for package-based commands (mirrors QuantumInput::menuActivated()).
      QJsonObject opts;
      QString inputFormat =
        theSender->property("packageInputFormat").toString();
      if (!inputFormat.isEmpty())
        opts.insert(QStringLiteral("inputMoleculeFormat"), inputFormat);

      QString userOptionsRel =
        theSender->property("packageUserOptions").toString();
      if (!userOptionsRel.isEmpty()) {
        QFile optFile(pkgDir + '/' + userOptionsRel);
        if (optFile.open(QIODevice::ReadOnly)) {
          QJsonParseError err;
          QJsonDocument doc = QJsonDocument::fromJson(optFile.readAll(), &err);
          if (err.error != QJsonParseError::NoError) {
            qWarning() << "Command: failed to parse user-options JSON:"
                       << (pkgDir + '/' + userOptionsRel) << err.errorString();
          } else if (doc.isObject()) {
            QJsonObject fileOpts = doc.object();
            for (auto it = fileOpts.constBegin(); it != fileOpts.constEnd();
                 ++it)
              opts.insert(it.key(), it.value());
          }
        } else {
          qWarning() << "Command: could not open user-options file:"
                     << (pkgDir + '/' + userOptionsRel);
        }
      }

      // Pre-populate the cached options so reloadOptions() does not invoke
      // the script with --print-options.
      widget->interfaceScript().setOptionsJson(opts);
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
      // Copy cached options so insertMolecule() doesn't call --print-options
      m_currentScript->setOptionsJson(iface.options());
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

void Command::registerFeature(const QString& type, const QString& packageDir,
                              const QString& command, const QString& identifier,
                              const QVariantMap& metadata)
{
  if (type != QLatin1String("menu-commands"))
    return;

  // Labels can be a plain string or a localized table {default: "...", locale:
  // "..."} Resolve to a string using the current locale, falling back to
  // "default".
  auto resolveLabel = [](const QVariant& var) -> QString {
    if (var.typeId() == QMetaType::QVariantMap) {
      QVariantMap m = var.toMap();
      // TODO: use the actual locale from --lang arg
      return m.value(QStringLiteral("default")).toString();
    }
    return var.toString();
  };

  // Extract label and priority from path.item (the TOML key is "item", not
  // "entry")
  QVariantMap pathMap = metadata.value("path").toMap();
  QVariantMap itemMap = pathMap.value("item").toMap();
  QString label = resolveLabel(itemMap.value("label"));
  if (label.isEmpty())
    label = identifier;

  // Build menu path from metadata: path.menu, then path.submenu.label
  QStringList menuPathList;
  QString topMenu = pathMap.value("menu").toString();
  if (!topMenu.isEmpty())
    menuPathList << topMenu;

  // Submenu label uses the "label" key (not "menu"), and may be localized
  QVariantMap submenuData = pathMap.value("submenu").toMap();
  QString submenu = resolveLabel(submenuData.value("label"));
  if (!submenu.isEmpty())
    menuPathList << submenu;

  // If no menu path specified, default to Extensions > Scripts
  if (menuPathList.isEmpty())
    menuPathList << tr("&Extensions") << tr("Scripts");

  // Extract priority from path.item.priority
  int priority = itemMap.value("priority", 0).toInt();

  // Create the action
  auto* action = new QAction(label, this);
  action->setProperty("packageMode", true);
  action->setProperty("packageDir", packageDir);
  action->setProperty("packageCommand", command);
  action->setProperty("packageIdentifier", identifier);
  action->setProperty("packageMenuPath", menuPathList);
  action->setProperty("packageUserOptions",
                      metadata.value("user-options").toString());
  action->setProperty("packageInputFormat",
                      metadata.value("input-format").toString());
  action->setEnabled(true);

  if (priority != 0)
    action->setProperty("menu priority", priority);

  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
  m_packageActions.insert(
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier),
    action);
  emit actionsChanged();
}

void Command::unregisterFeature(const QString& type, const QString& packageDir,
                                const QString& command,
                                const QString& identifier)
{
  if (type != QLatin1String("menu-commands"))
    return;

  const QString featureKey =
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier);
  const QList<QAction*> actions = m_packageActions.values(featureKey);
  if (actions.isEmpty())
    return;

  m_packageActions.remove(featureKey);

  InterfaceWidget* widget = m_dialogs.take(featureKey);
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
  emit actionsChanged();
}

} // namespace Avogadro::QtPlugins
