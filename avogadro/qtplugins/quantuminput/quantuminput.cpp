/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantuminput.h"

#include <avogadro/molequeue/client/jobobject.h>
#include <avogadro/molequeue/inputgenerator.h>
#include <avogadro/molequeue/inputgeneratordialog.h>
#include <avogadro/molequeue/inputgeneratorwidget.h>

#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
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
#include <QtWidgets/QVBoxLayout>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QSettings>
#include <QtCore/QStandardPaths>
#include <QtCore/QStringList>
#include <QtCore/QtPlugin>

namespace Avogadro::QtPlugins {

using MoleQueue::InputGenerator;
using MoleQueue::InputGeneratorDialog;
using MoleQueue::JobObject;

QuantumInput::QuantumInput(QObject* parent_)
  : ExtensionPlugin(parent_), m_molecule(nullptr), m_outputFormat(nullptr)
{
  refreshGenerators();

  // Connect to PackageManager for pyproject.toml-based packages
  auto* pm = QtGui::PackageManager::instance();
  connect(pm, &QtGui::PackageManager::featureRegistered, this,
          &QuantumInput::registerFeature);
  connect(pm, &QtGui::PackageManager::featureRemoved, this,
          &QuantumInput::unregisterFeature);
}

QuantumInput::~QuantumInput()
{
  qDeleteAll(m_dialogs.values());
  m_dialogs.clear();
}

QList<QAction*> QuantumInput::actions() const
{
  return m_packageActions.values();
}

QStringList QuantumInput::menuPath(QAction* action) const
{
  QStringList path;
  if (action == nullptr)
    return path;

  // Package-based actions may carry a custom menu path
  QVariant pkgMenuPath = action->property("packageMenuPath");
  if (pkgMenuPath.isValid())
    return pkgMenuPath.toStringList();
  path << tr("&Input");
  return path;
}

void QuantumInput::setMolecule(QtGui::Molecule* mol)
{
  if (m_molecule == mol)
    return;

  if (m_molecule)
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &QuantumInput::moleculeChanged);

  m_molecule = mol;

  if (m_molecule)
    connect(m_molecule, &QtGui::Molecule::changed, this,
            &QuantumInput::moleculeChanged);

  foreach (InputGeneratorDialog* dlg, m_dialogs.values())
    dlg->setMolecule(mol);

  updateActionStates();
}

void QuantumInput::moleculeChanged(unsigned int change)
{
  if (change & QtGui::Molecule::UnitCell)
    updateActionStates();
}

void QuantumInput::updateActionStates()
{
  bool isPeriodic = m_molecule && m_molecule->unitCell() != nullptr;
  for (QAction* action : m_packageActions.values()) {
    // Default: supports molecules (true), does not support periodic (false)
    bool supportsMolecular = action->property("supportMolecular").isValid()
                               ? action->property("supportMolecular").toBool()
                               : true;
    bool supportsPeriodic = action->property("supportPeriodic").isValid()
                              ? action->property("supportPeriodic").toBool()
                              : false;

    action->setEnabled(isPeriodic ? supportsPeriodic : supportsMolecular);
  }
}

void QuantumInput::openJobOutput(const JobObject& job)
{
  m_outputFormat = nullptr;
  m_outputFileName.clear();

  QString outputPath(job.value("outputDirectory").toString());

  using QtGui::FileFormatDialog;
  FileFormatDialog::FormatFilePair result = FileFormatDialog::fileToRead(
    qobject_cast<QWidget*>(parent()), tr("Open Output File"), outputPath);

  if (result.first == nullptr) // User canceled
    return;

  m_outputFormat = result.first;
  m_outputFileName = result.second;

  emit moleculeReady(1);
}

bool QuantumInput::readMolecule(QtGui::Molecule& mol)
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

void QuantumInput::refreshGenerators()
{
  updateInputGeneratorScripts();
  updateActions();
}

void QuantumInput::menuActivated()
{
  auto* theSender = qobject_cast<QAction*>(sender());
  if (!theSender)
    return;

  QWidget* theParent = qobject_cast<QWidget*>(parent());
  bool isPackage = theSender->property("packageMode").toBool();
  QString key;
  InputGeneratorDialog* dlg = nullptr;

  if (isPackage) {
    QString pkgDir = theSender->property("packageDir").toString();
    QString pkgCmd = theSender->property("packageCommand").toString();
    QString pkgId = theSender->property("packageIdentifier").toString();
    key = QtGui::PackageManager::packageFeatureKey(pkgDir, pkgCmd, pkgId);

    dlg = m_dialogs.value(key, nullptr);
    if (!dlg) {
      dlg = new InputGeneratorDialog(theParent);
      dlg->widget().inputGenerator().interpreter().setPackageInfo(
        pkgDir, pkgCmd, pkgId);

      // Load user options from the JSON file declared in pyproject.toml
      QString userOptionsRel =
        theSender->property("packageUserOptions").toString();
      if (!userOptionsRel.isEmpty()) {
        QString userOptionsPath = pkgDir + '/' + userOptionsRel;
        QFile optFile(userOptionsPath);
        if (optFile.open(QIODevice::ReadOnly)) {
          QJsonDocument doc = QJsonDocument::fromJson(optFile.readAll());
          if (doc.isObject()) {
            QJsonObject opts = doc.object();
            QString inputFormat =
              theSender->property("packageInputFormat").toString();
            if (!inputFormat.isEmpty())
              opts.insert("inputMoleculeFormat", inputFormat);
            QString highlightStylesRel =
              theSender->property("packageHighlightStyles").toString();
            if (!highlightStylesRel.isEmpty()) {
              QFile stylesFile(pkgDir + '/' + highlightStylesRel);
              if (stylesFile.open(QIODevice::ReadOnly)) {
                QJsonDocument stylesDoc =
                  QJsonDocument::fromJson(stylesFile.readAll());
                // File may be a bare array or {"highlightStyles": [...]}
                if (stylesDoc.isArray()) {
                  opts.insert("highlightStyles", stylesDoc.array());
                } else if (stylesDoc.isObject()) {
                  QJsonValue v = stylesDoc.object().value("highlightStyles");
                  if (v.isArray())
                    opts.insert("highlightStyles", v.toArray());
                }
              }
            }
            dlg->widget().inputGenerator().setOptions(opts);
          }
        } else {
          qWarning() << "QuantumInput: could not open user-options file:"
                     << userOptionsPath;
        }
      }

      dlg->widget().reloadOptions();
      dlg->setWindowTitle(tr("%1 Input Generator").arg(theSender->text()));
      connect(&dlg->widget(), &MoleQueue::InputGeneratorWidget::openJobOutput,
              this, &QuantumInput::openJobOutput);
      m_dialogs.insert(key, dlg);
    }
  } else {
    key = theSender->data().toString();
    dlg = m_dialogs.value(key, nullptr);
    if (!dlg) {
      dlg = new InputGeneratorDialog(key, theParent);
      connect(&dlg->widget(), &MoleQueue::InputGeneratorWidget::openJobOutput,
              this, &QuantumInput::openJobOutput);
      m_dialogs.insert(key, dlg);
    }
  }

  dlg->setMolecule(m_molecule);
  dlg->show();
  dlg->raise();
}

void QuantumInput::updateInputGeneratorScripts()
{
  m_inputGeneratorScripts = QtGui::ScriptLoader::scriptList("inputGenerators");
}

void QuantumInput::updateActions()
{
  m_actions.clear();

  foreach (const QString& programName, m_inputGeneratorScripts.uniqueKeys()) {
    QStringList scripts = m_inputGeneratorScripts.values(programName);

    QString label = programName;
    // make sure it has the ellipsis for UI
    if (label.endsWith("...")) {
      label.chop(3);
      label.append("…");
    }
    if (!label.endsWith("…"))
      label.append("…");

    if (scripts.size() == 1) {
      addAction(label, scripts.first());
    } else {
      foreach (const QString& filePath, scripts) {
        qWarning() << "Multiple generators for" << programName << filePath;
      }
      qWarning() << "Using generator: " << scripts.first();
      addAction(label, scripts.first());
    }
  }
}

void QuantumInput::addAction(const QString& label,
                             const QString& scriptFilePath)
{
  auto* action = new QAction(label, this);
  action->setData(scriptFilePath);
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
}

bool QuantumInput::queryProgramName(const QString& scriptFilePath,
                                    QString& displayName)
{
  InputGenerator gen(scriptFilePath);
  displayName = gen.displayName();
  if (gen.hasErrors()) {
    displayName.clear();
    qWarning() << "QuantumInput::queryProgramName: Unable to retrieve program "
                  "name for"
               << scriptFilePath << ";" << gen.errorList().join("\n\n");
    return false;
  }
  return true;
}

void QuantumInput::registerFeature(const QString& type,
                                   const QString& packageDir,
                                   const QString& command,
                                   const QString& identifier,
                                   const QVariantMap& metadata)
{
  if (type != QLatin1String("input-generators"))
    return;

  // Extract label from metadata
  QString label = metadata.value("program-name").toString();
  if (label.isEmpty())
    label = identifier;
  if (!label.endsWith("…") && !label.endsWith("..."))
    label.append("…");

  // Create the action
  auto* action = new QAction(label, this);
  action->setProperty("packageMode", true);
  action->setProperty("packageDir", packageDir);
  action->setProperty("packageCommand", command);
  action->setProperty("packageIdentifier", identifier);
  action->setProperty("packageUserOptions",
                      metadata.value("user-options").toString());
  action->setProperty("packageInputFormat",
                      metadata.value("input-format").toString());
  action->setProperty("packageHighlightStyles",
                      metadata.value("highlight-styles").toString());
  // Default to &Input menu path
  action->setProperty("packageMenuPath", QStringList() << tr("&Input"));
  // Molecule/periodic support: default molecular=true, periodic=false
  // "support" is a nested QVariantMap in the metadata
  QVariantMap supportMeta = metadata.value("support").toMap();
  action->setProperty("supportMolecular",
                      supportMeta.value("molecular", true).toBool());
  action->setProperty("supportPeriodic",
                      supportMeta.value("periodic", false).toBool());
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
  m_packageActions.insert(
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier),
    action);
}

void QuantumInput::unregisterFeature(const QString& type,
                                     const QString& packageDir,
                                     const QString& command,
                                     const QString& identifier)
{
  if (type != QLatin1String("input-generators"))
    return;

  const QString featureKey =
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier);
  const QList<QAction*> actions = m_packageActions.values(featureKey);
  if (actions.isEmpty())
    return;

  m_packageActions.remove(featureKey);

  InputGeneratorDialog* dlg = m_dialogs.take(featureKey);
  if (dlg) {
    dlg->close();
    delete dlg;
  }

  for (QAction* action : actions) {
    m_actions.removeAll(action);
    action->deleteLater();
  }
}

} // namespace Avogadro::QtPlugins
