/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantuminput.h"

#include <avogadro/molequeue/inputgenerator.h>
#include <avogadro/molequeue/inputgeneratordialog.h>
#include <avogadro/molequeue/inputgeneratorwidget.h>
#include <avogadro/qtgui/avogadropython.h>
#include <avogadro/qtgui/filebrowsewidget.h>
#include <avogadro/qtgui/fileformatdialog.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/scriptloader.h>
#include <avogadro/qtgui/utilities.h>

#include <avogadro/molequeue/client/jobobject.h>

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

  QString scriptFileName = theSender->data().toString();
  QWidget* theParent = qobject_cast<QWidget*>(parent());
  InputGeneratorDialog* dlg = m_dialogs.value(scriptFileName, nullptr);

  if (!dlg) {
    dlg = new InputGeneratorDialog(scriptFileName, theParent);
    connect(&dlg->widget(), SIGNAL(openJobOutput(const MoleQueue::JobObject&)),
            this, SLOT(openJobOutput(const MoleQueue::JobObject&)));
    m_dialogs.insert(scriptFileName, dlg);
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
    // Include the full path if there are multiple generators with the same
    // name.
    QString label = programName;
    if (!label.endsWith("…") && !label.endsWith("..."))
      label.append("…");

    if (scripts.size() == 1) {
      addAction(label, scripts.first());
    } else {
      foreach (const QString& filePath, scripts) {
        addAction(QString("%1 (%2)").arg(label, filePath), filePath);
      }
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
} // namespace Avogadro::QtPlugins
