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
#include <avogadro/qtgui/tomlparse.h>
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
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
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

void QuantumInput::refreshGenerators() {}

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
        pkgDir, pkgCmd, pkgId,
        theSender->property("packageDisplayName").toString());

      // The pyproject.toml [avogadro.X] table may declare a separate
      // user-options file (JSON or TOML) that overrides the defaults baked
      // into the input-generator script.  Load it now so the dialog starts
      // with the right set of options.
      QJsonObject opts;
      // Inject the preferred input molecule format (e.g. "cjson") so the
      // generator knows which format to request from Avogadro.
      QString inputFormat =
        theSender->property("packageInputFormat").toString();
      if (!inputFormat.isEmpty())
        opts.insert("inputMoleculeFormat", inputFormat);

      QString userOptionsRel =
        theSender->property("packageUserOptions").toString();
      if (!userOptionsRel.isEmpty()) {
        QJsonObject userOpts = QtGui::PackageManager::resolveUserOptions(
          userOptionsRel, pkgDir, pkgCmd, pkgId);
        if (!userOpts.isEmpty())
          opts.insert(QStringLiteral("userOptions"), userOpts);
      }

      // Optionally load syntax-highlight rules from a separate file.
      // The file path is relative to the package directory and may be
      // JSON or TOML.  The expected JSON shape fed to the widget is:
      //   "highlightStyles": [ { "style": "<name>", "rules": [...] }, … ]
      // This runs unconditionally so a package that only supplies highlight
      // styles (with no other options) is not silently skipped.
      QString highlightStylesRel =
        theSender->property("packageHighlightStyles").toString();
      if (!highlightStylesRel.isEmpty()) {
        QFile stylesFile(pkgDir + '/' + highlightStylesRel);
        if (stylesFile.open(QIODevice::ReadOnly)) {
          QByteArray content = stylesFile.readAll();
          if (highlightStylesRel.endsWith(QLatin1String(".toml"),
                                          Qt::CaseInsensitive)) {
            // TOML layout: each top-level key is a style name whose
            // value has a "rules" array, e.g.:
            //   [[default.rules]]
            //     …
            // Each entry is reshaped into {"style": key, "rules": […]}.
            bool ok = false;
            QJsonObject stylesObj = QtGui::parseTomlToJson(content, &ok);
            if (!ok) {
              qWarning() << "QuantumInput: failed to parse TOML highlight"
                            " styles file:"
                         << highlightStylesRel;
            } else { // it was converted to JSON successfully
              QJsonArray stylesArray;
              for (auto it = stylesObj.constBegin(); it != stylesObj.constEnd();
                   ++it) {
                QJsonObject styleObj;
                styleObj[QStringLiteral("style")] = it.key();
                styleObj[QStringLiteral("rules")] =
                  it.value()
                    .toObject()
                    .value(QStringLiteral("rules"))
                    .toArray();
                stylesArray.append(styleObj);
              }
              if (!stylesArray.isEmpty())
                opts.insert("highlightStyles", stylesArray);
            }
          } else {
            // JSON: accept either a bare array or an object that wraps
            // the array under the "highlightStyles" key.
            QJsonDocument stylesDoc = QJsonDocument::fromJson(content);
            if (stylesDoc.isArray()) {
              opts.insert("highlightStyles", stylesDoc.array());
            } else if (stylesDoc.isObject()) {
              QJsonValue v = stylesDoc.object().value("highlightStyles");
              if (v.isArray())
                opts.insert("highlightStyles", v.toArray());
            }
          }
        }
      }
      if (!opts.isEmpty())
        dlg->widget().inputGenerator().setOptions(opts);
    }

    dlg->widget().reloadOptions();

    // check the title for …
    QString title(theSender->text());
    if (title.endsWith("..."))
      title.chop(3);
    else if (title.endsWith("…"))
      title.chop(1);

    dlg->setWindowTitle(tr("%1 Input Generator").arg(title));
    connect(&dlg->widget(), &MoleQueue::InputGeneratorWidget::openJobOutput,
            this, &QuantumInput::openJobOutput);
    m_dialogs.insert(key, dlg);
  }

  dlg->setMolecule(m_molecule);
  dlg->show();
  dlg->raise();
  dlg->activateWindow();
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
  QString displayName = metadata.value("program-name").toString();
  if (displayName.isEmpty())
    displayName = identifier;
  QString label = displayName;
  if (!label.endsWith("…") && !label.endsWith("..."))
    label.append("…");

  // Create the action
  auto* action = new QAction(label, this);
  action->setProperty("packageMode", true);
  action->setProperty("packageDir", packageDir);
  action->setProperty("packageCommand", command);
  action->setProperty("packageIdentifier", identifier);
  action->setProperty("packageDisplayName", displayName);
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
  m_packageActions.insert(
    QtGui::PackageManager::packageFeatureKey(packageDir, command, identifier),
    action);
  emit actionsChanged();
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

  for (QAction* action : actions)
    action->deleteLater();
  emit actionsChanged();
}

} // namespace Avogadro::QtPlugins
