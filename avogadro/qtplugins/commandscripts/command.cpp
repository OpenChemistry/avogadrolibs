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

  if (m_molecule)
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &Command::moleculeChanged);

  m_molecule = mol;

  if (m_molecule)
    connect(m_molecule, &QtGui::Molecule::changed, this,
            &Command::moleculeChanged);

  foreach (InterfaceWidget* dlg, m_dialogs.values())
    dlg->setMolecule(mol);
}

void Command::moleculeChanged(unsigned int change)
{
  // While a script is in flight, any structural mutation of the launch-time
  // molecule invalidates the impending write-back: atom indices, bond ordering
  // and the unit cell could all differ from what the script started with.
  // Selection and Layer toggles are pure UI state and safe to ignore.
  if (m_currentScript == nullptr || m_runningMolecule.isNull())
    return;

  const unsigned int kIgnore =
    QtGui::Molecule::Selection | QtGui::Molecule::Layers;
  if ((change & ~kIgnore) != 0)
    m_runningMolecule.clear();
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

  // Refuse to launch a new run while a previous script is still in flight,
  // otherwise its results would land on whichever molecule is current when
  // it eventually finishes.
  if (m_currentScript) {
    QMessageBox::information(
      theParent, tr("Command In Progress"),
      tr("A command script is already running. Please wait for it to finish "
         "before starting another."));
    return;
  }

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
    // The pyproject.toml [avogadro.X] table may declare a separate
    // user-options file (JSON or TOML), or the literal "dynamic" to run
    // the script with --user-options.
    QString userOptionsRel =
      theSender->property("packageUserOptions").toString();
    key = QtGui::PackageManager::packageFeatureKey(pkgDir, pkgCmd, pkgId);

    widget = m_dialogs.value(key, nullptr);
    const bool isNewWidget = (widget == nullptr);
    if (isNewWidget) {
      widget = new InterfaceWidget(QString(), theParent);
      widget->interfaceScript().interpreter().setPackageInfo(
        pkgDir, pkgCmd, pkgId,
        theSender->property("packageDisplayName").toString());
      m_dialogs.insert(key, widget);
    }

    // A script that builds its options dynamically expects to be asked again
    // every time the user opens the command: a list of jobs on a server, the
    // files in a directory, anything that changes between invocations. Serving
    // the cached form would pin the first answer for the rest of the session,
    // which makes the whole point of "dynamic" moot, so ask again and rebuild
    // the form in place.
    if (isNewWidget ||
        QtGui::PackageManager::isDynamicUserOptions(userOptionsRel)) {
      // Build options from pyproject.toml metadata; never call --print-options
      // for package-based commands (mirrors QuantumInput::menuActivated()).
      QJsonObject opts;
      QString inputFormat =
        theSender->property("packageInputFormat").toString();
      if (!inputFormat.isEmpty())
        opts.insert(QStringLiteral("inputMoleculeFormat"), inputFormat);

      // The option definitions must be wrapped under "userOptions" so that
      // JsonWidget::buildOptionGui() recognises them and builds the dialog.
      if (!userOptionsRel.isEmpty()) {
        QJsonObject userOpts = QtGui::PackageManager::resolveUserOptions(
          userOptionsRel, pkgDir, pkgCmd, pkgId);
        if (!userOpts.isEmpty())
          opts.insert(QStringLiteral("userOptions"), userOpts);
      }

      // A dynamic script that fails - no network, a timeout, malformed JSON -
      // resolves to nothing. Pushing that empty result into a widget that
      // already has a working form would blank it, and isEmpty() below would
      // then run the command with no options at all rather than showing the
      // dialog. Keep the last good form instead and let the user try again.
      if (isNewWidget || opts.contains(QStringLiteral("userOptions"))) {
        // Pre-populate the cached options so reloadOptions() does not invoke
        // the script with --print-options.
        widget->interfaceScript().setOptionsJson(opts);
        widget->reloadOptions();
      }
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

  closeProgressDialog();

  if (m_currentScript) {
    disconnect(m_currentScript, SIGNAL(finished()), this,
               SLOT(processFinished()));
    // Kill the child process so an abandoned xtb run does not keep going.
    m_currentScript->interpreter().asyncTerminate();
    m_currentScript->deleteLater();
    m_currentScript = nullptr;
    m_runningMolecule.clear();
  }

  if (m_currentInterface) {
    QJsonObject collected = m_currentInterface->collectOptions();
    const auto& iface = m_currentInterface->interfaceScript();

    // Create a new InterfaceScript with the same configuration
    m_currentScript = new InterfaceScript(parent());
    const auto& interp = iface.interpreter();
    QJsonObject options;
    if (interp.isPackageMode()) {
      m_currentScript->interpreter().setPackageInfo(
        interp.packageDir(), interp.packageCommand(),
        interp.packageIdentifier(), interp.packageDisplayName());
      // Copy cached options so insertMolecule() doesn't call --print-options
      m_currentScript->setOptionsJson(iface.options());
      // Wrap user selections under "options" so Python receives them as
      // avo_input["options"]["key"] (matching the package plugin convention).
      options.insert(QStringLiteral("options"), collected);
    } else {
      m_currentScript->setScriptFilePath(iface.scriptFilePath());
      options = collected;
    }
    connect(m_currentScript, SIGNAL(finished()), this, SLOT(processFinished()));
    connect(m_currentScript, &QtGui::InterfaceScript::progress, this,
            &Command::updateProgress);

    // Starts indeterminate; a script that reports progress switches it to a
    // determinate bar. See InterfaceScript for the script-side protocol.
    QString title = tr("Processing %1").arg(iface.displayName());
    m_progress = new QProgressDialog(title, tr("Cancel"), 0, 0,
                                     qobject_cast<QWidget*>(parent()));
    m_progress->setMinimumDuration(1000); // 1 second
    // Don't let a script that reports its final step and then keeps working
    // (writing files, etc.) make the dialog vanish early.
    m_progress->setAutoClose(false);
    m_progress->setAutoReset(false);
    connect(m_progress, &QProgressDialog::canceled, this,
            &Command::cancelCommand);

    // Snapshot so processFinished() can detect if the molecule was closed
    // or swapped before the async script returned.
    m_runningMolecule = m_molecule;
    if (!m_currentScript->runCommand(options, m_molecule)) {
      // The script never started, so finished() will never arrive and
      // processFinished() would never tear down the progress dialog. Clean up
      // here and show why, rather than leaving a dialog that cannot be closed.
      commandFailed(m_currentScript->errorList());
    }
  }
}

void Command::updateProgress(const QString& message, int value, int maximum)
{
  if (m_progress == nullptr)
    return;

  if (maximum > 0 && m_progress->maximum() != maximum)
    m_progress->setRange(0, maximum);

  // Only meaningful once a script has given the bar a determinate range.
  if (value >= 0 && m_progress->maximum() > 0)
    m_progress->setValue(value);

  if (!message.isEmpty())
    m_progress->setLabelText(message);
}

void Command::closeProgressDialog()
{
  if (m_progress == nullptr)
    return;

  // Clear the member and drop the connection before closing: close() emits
  // canceled() even for a dialog that was never shown, and cancelCommand()
  // would then delete the dialog (and the running script) out from under
  // whoever called us.
  QProgressDialog* dialog = m_progress;
  m_progress = nullptr;
  disconnect(dialog, &QProgressDialog::canceled, this, &Command::cancelCommand);
  dialog->close();
  dialog->deleteLater();
}

void Command::cancelCommand()
{
  closeProgressDialog();

  if (m_currentScript == nullptr)
    return;

  // Kill the child process and drop whatever partial output it produced.
  disconnect(m_currentScript, SIGNAL(finished()), this,
             SLOT(processFinished()));
  m_currentScript->interpreter().asyncTerminate();
  m_currentScript->deleteLater();
  m_currentScript = nullptr;
  m_runningMolecule.clear();
}

void Command::commandFailed(const QStringList& errors)
{
  closeProgressDialog();

  QString details = errors.join(QStringLiteral("\n"));
  if (details.isEmpty())
    details = tr("The script could not be started.");
  qWarning() << "Command: script failed to start:" << details;

  if (m_currentScript) {
    m_currentScript->deleteLater();
    m_currentScript = nullptr;
  }
  m_runningMolecule.clear();

  QMessageBox::warning(qobject_cast<QWidget*>(parent()),
                       tr("Error Running Script"), details);
}

void Command::processFinished()
{
  if (m_currentScript == nullptr)
    return;

  // Take the script and its molecule locally before doing anything that can
  // run the event loop (closing the dialog, writing results back): a
  // re-entrant call must see this command as already finished rather than act
  // on a script that is being torn down here.
  QtGui::InterfaceScript* script = m_currentScript;
  m_currentScript = nullptr;
  QtGui::Molecule* target = m_runningMolecule.data();
  m_runningMolecule.clear();

  closeProgressDialog();

  // Drop results if the launch-time molecule was destroyed, or if the user
  // has since swapped to a different molecule (its atom count/ordering may
  // no longer match what the script is about to write back).
  if (target != nullptr && target == m_molecule) {
    script->processCommand(target);

    // collect errors
    if (script->hasErrors()) {
      qWarning() << script->errorList();
    }
  } else if (target == nullptr) {
    qWarning() << "Command: discarding script results; molecule was closed "
                  "or edited while the command was running.";
  } else {
    qWarning() << "Command: discarding script results; active molecule "
                  "changed while the command was running.";
  }

  script->deleteLater();
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

  // Extract the path for the command's menu item
  // The TOML values that specify this are the following:
  //
  //    [[menu-commands]]
  //    menu = string | table
  //    submenu = string | table
  //    subsubmenu = string | table
  //    item = string | table
  //    menu-priorities = array[integer]
  //
  // The intermediate levels (submenu and subsubmenu) are optional.
  //
  // Each label in the cascade (menu, submenu, subsubmenu, item) is either a
  // normal UTF-8 string or a table of localized strings.
  // A localization table takes the form:
  //    item = { default = "...", <locale> = "...", <locale> = "...", ... }
  // (It may of course be formatted as a separate table with a header).
  // Examples of locale strings are "fr", "de", "de_DE", "en_GB"
  // Localized strings *must* include a "default" key, which is the fallback
  // value if the current locale is not found (generally US English, but this
  // should not be relied upon).
  //
  // The menu-priorities array *must* contain exactly 1 fewer integer than the
  // number of labels (though priority 0 is used as a fallback to avoid crashes)
  // If the labels are ordered in an array [menu, (submenu), (subsubmenu), item]
  // the integer at index i in priorities specifies the priority of the label
  // [i + 1] within label [i], e.g. menu-priorities = [ 400, 200 ] specifies
  // that the item should have priority 200 within the submenu and the submenu
  // should have priority 400 within the menu.
  // Items/submenus within a menu will be displayed in order of priority, with
  // those with a higher priority nearer to the top. Ties are sorted
  // alphabetically.
  // Items with priorities within the same 100 span are grouped together (0-99
  // in the first group, 100-199 in the next, and so on). A separator is
  // inserted automatically between each group.

  auto resolveLabel = [](const QVariant& var) -> QString {
    if (var.typeId() == QMetaType::QVariantMap) {
      QVariantMap m = var.toMap();
      // TODO: use the actual locale from --lang arg
      return m.value(QStringLiteral("default")).toString();
    }
    return var.toString();
  };

  QString topMenu = resolveLabel(metadata.value("menu"));
  QString subMenu = resolveLabel(metadata.value("submenu"));
  QString subSubMenu = resolveLabel(metadata.value("subsubmenu"));
  QString item = resolveLabel(metadata.value("item"));

  // If nothing is specified at all, just add under Extensions > Scripts with
  // the identifier as the label
  if (topMenu.isEmpty() && item.isEmpty()) {
    topMenu = tr("&Extensions");
    subMenu = tr("Scripts");
    item = identifier;
  }

  // Build menu path list
  QStringList menuPathList;
  menuPathList << topMenu;
  if (!subMenu.isEmpty()) {
    menuPathList << subMenu;
  }
  if (!subSubMenu.isEmpty()) {
    menuPathList << subSubMenu;
  }

  // Extract priorities
  QVariantList priorities = metadata.value("menu-priorities").toList();
  int menuPriority = priorities.size() > 0 ? priorities[0].toInt() : 0;
  int subMenuPriority = priorities.size() > 1 ? priorities[1].toInt() : 0;
  int subSubMenuPriority = priorities.size() > 2 ? priorities[2].toInt() : 0;

  // Create the action
  auto* action = new QAction(item, this);
  action->setProperty("packageMode", true);
  action->setProperty("packageDir", packageDir);
  action->setProperty("packageCommand", command);
  action->setProperty("packageIdentifier", identifier);
  action->setProperty("packageDisplayName", item);
  action->setProperty("packageMenuPath", menuPathList);
  action->setProperty("packageUserOptions",
                      metadata.value("user-options").toString());
  action->setProperty("packageInputFormat",
                      metadata.value("input-format").toString());
  action->setEnabled(true);

  // TODO priorities in higher level menus? Probably needs change in MenuBuilder
  if (priorities.size() > 0)
    action->setProperty("menu priority", priorities.last());

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
