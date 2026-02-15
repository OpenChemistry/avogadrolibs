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
}

QuantumInput::~QuantumInput()
{
  qDeleteAll(m_dialogs.values());
  m_dialogs.clear();
}

QList<QAction*> QuantumInput::actions() const
{
  return m_actions;
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

  m_molecule = mol;

  foreach (InputGeneratorDialog* dlg, m_dialogs.values())
    dlg->setMolecule(mol);
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
    key = QStringLiteral("pkg:") + pkgId;

    dlg = m_dialogs.value(key, nullptr);
    if (!dlg) {
      dlg = new InputGeneratorDialog(theParent);
      dlg->widget().inputGenerator().interpreter().setPackageInfo(
        pkgDir, pkgCmd, pkgId);
      dlg->widget().reloadOptions();
      dlg->setWindowTitle(tr("%1 Input Generator").arg(theSender->text()));
      connect(&dlg->widget(),
              SIGNAL(openJobOutput(const MoleQueue::JobObject&)), this,
              SLOT(openJobOutput(const MoleQueue::JobObject&)));
      m_dialogs.insert(key, dlg);
    }
  } else {
    key = theSender->data().toString();
    dlg = m_dialogs.value(key, nullptr);
    if (!dlg) {
      dlg = new InputGeneratorDialog(key, theParent);
      connect(&dlg->widget(),
              SIGNAL(openJobOutput(const MoleQueue::JobObject&)), this,
              SLOT(openJobOutput(const MoleQueue::JobObject&)));
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
  // Default to &Input menu path
  action->setProperty("packageMenuPath", QStringList() << tr("&Input"));
  action->setEnabled(true);
  connect(action, SIGNAL(triggered()), SLOT(menuActivated()));
  m_actions << action;
}

} // namespace Avogadro::QtPlugins
