/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <iostream>

#include "apbsdialog.h"
#include "apbsoutputdialog.h"
#include "ui_apbsdialog.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QProcess>

#include <avogadro/molequeue/inputgenerator.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/utilities.h>

namespace Avogadro {
namespace QtPlugins {

using MoleQueue::InputGenerator;

ApbsDialog::ApbsDialog(QWidget* parent_)
  : QDialog(parent_), m_ui(new Ui::ApbsDialog), m_molecule(nullptr),
    m_inputGenerator(
      new InputGenerator(QCoreApplication::applicationDirPath() + "/../" +
                         QtGui::Utilities::libraryDirectory() +
                         "/avogadro2/scripts/inputGenerators/apbs.py")),
    m_loadStructureFile(false), m_loadCubeFile(false)
{
  m_ui->setupUi(this);

  connect(m_ui->closeButton, SIGNAL(clicked()), this, SLOT(reject()));
  connect(m_ui->openPdbFileButton, SIGNAL(clicked()), this,
          SLOT(openPdbFile()));
  connect(m_ui->openPqrFileButton, SIGNAL(clicked()), this,
          SLOT(openPqrFile()));
  connect(m_ui->runApbsButton, SIGNAL(clicked()), this, SLOT(runApbs()));
  connect(m_ui->runPdb2PqrButton, SIGNAL(clicked()), this, SLOT(runPdb2Pqr()));
  connect(m_ui->saveInputFileButton, SIGNAL(clicked()), this,
          SLOT(saveInputFile()));
}

ApbsDialog::~ApbsDialog()
{
  delete m_ui;
  delete m_inputGenerator;
}

void ApbsDialog::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule != m_molecule) {
    m_molecule = molecule;

    // clear values from previous runs
    m_ui->pdbFileLineEdit->clear();
    m_ui->pqrFileLineEdit->clear();
    m_ui->textEdit->clear();
  }
}

QString ApbsDialog::pqrFileName() const
{
  if (m_ui->generateFromPdbButton->isChecked())
    return m_generatedPqrFileName;
  else
    return m_ui->pqrFileLineEdit->text();
}

QString ApbsDialog::cubeFileName() const
{
  return m_cubeFileName;
}

void ApbsDialog::openPdbFile()
{
  QString fileName = QFileDialog::getOpenFileName(
    qobject_cast<QWidget*>(parent()), tr("Open PDB File"), QString(),
    tr("PDB Files (*.pdb)"));
  if (!fileName.isEmpty()) {
    m_ui->pdbFileLineEdit->setText(fileName);
    m_ui->generateFromPdbButton->setChecked(true);
  }
}

void ApbsDialog::openPqrFile()
{
  QString fileName = QFileDialog::getOpenFileName(
    qobject_cast<QWidget*>(parent()), tr("Open PQR File"), QString(),
    tr("PQR Files (*.pqr)"));
  if (!fileName.isEmpty()) {
    m_ui->pqrFileLineEdit->setText(fileName);
    m_ui->loadFromPqrButton->setChecked(true);
  }

  updatePreviewTextImmediately();
}

void ApbsDialog::runApbs()
{
  saveInputFile("apbs.in");

  // run apbs
  QStringList arguments;
  arguments.append("apbs.in");

  QProcess process;
  process.start("apbs", arguments);

  // FIXME: show progress dialog
  process.waitForFinished();

  if (process.exitStatus() == QProcess::NormalExit) {
    m_cubeFileName = "pot-PE0.dx";

    ApbsOutputDialog dialog(this);
    connect(&dialog, SIGNAL(accepted()), this, SLOT(accept()));
    int code = dialog.exec();
    if (code == QDialog::Accepted) {
      m_loadStructureFile = dialog.loadStructureFile();
      m_loadCubeFile = dialog.loadCubeFile();
    } else {
      m_loadStructureFile = false;
      m_loadCubeFile = false;
    }
  } else {
    m_loadStructureFile = false;
    m_loadCubeFile = false;

    QMessageBox::critical(this, tr("Error"),
                          tr("Error running APBS: %1")
                            .arg(process.readAllStandardError().constData()));
  }
}

void ApbsDialog::runPdb2Pqr()
{
  QString pdbFileName = m_ui->pdbFileLineEdit->text();
  if (pdbFileName.isEmpty()) {
    QMessageBox::critical(this, tr("Error"), tr("Please specify PDB file"));
    return;
  }

  QString pqrFileName_ = QFileInfo(pdbFileName).baseName() + ".pqr";
  QString forceFieldName = m_ui->forceFieldComboBox->currentText();

  // run pdb2pqr
  QStringList arguments;
  arguments.append("--ff");
  arguments.append(forceFieldName);
  arguments.append(pdbFileName);
  arguments.append(pqrFileName_);

  QProcess process;
  process.start("pdb2pqr", arguments);

  process.waitForFinished();

  if (process.exitStatus() == QProcess::NormalExit) {
    QMessageBox::information(this, "Success",
                             QString("Generated %1").arg(pqrFileName_));
    m_generatedPqrFileName = pqrFileName_;
    updatePreviewTextImmediately();
  } else {
    QMessageBox::critical(this, "Error", QString("Error running PDB2PQR"));
    m_generatedPqrFileName.clear();
  }
}

void ApbsDialog::saveInputFile()
{
  QString fileName = QFileDialog::getSaveFileName(
    this, tr("Save APBS Input File"), "apbs.in", tr("ABPS Input (*.in)"));
  if (!fileName.isEmpty()) {
    saveInputFile(fileName);

    QMessageBox::information(this, tr("Success"),
                             tr("Input file written to '%1'").arg(fileName));
  }
}

void ApbsDialog::saveInputFile(const QString& fileName)
{
  QString contents = m_inputGenerator->fileContents("apbs.in");

  QFile file(fileName);
  file.open(QFile::WriteOnly);
  file.write(contents.toLocal8Bit());
  file.close();
}

void ApbsDialog::updatePreviewTextImmediately()
{
  QString pqrFileName_;
  if (m_ui->generateFromPdbButton->isChecked())
    pqrFileName_ = m_generatedPqrFileName;
  else
    pqrFileName_ = m_ui->pqrFileLineEdit->text();

  QJsonObject inputOptions;
  QJsonObject options;
  options["mainFile"] = pqrFileName_;
  options["Input File"] = pqrFileName_;
  options["Calculation"] = QString("mg-auto");
  inputOptions["options"] = options;
  QJsonObject settings;
  inputOptions["settings"] = settings;
  bool success = m_inputGenerator->generateInput(inputOptions, *m_molecule);

  if (!success) {
    // FIXME: show in a dialog
    std::cerr << "errors: " << std::endl;
    foreach (const QString& error, m_inputGenerator->errorList()) {
      std::cerr << "  " << error.toStdString() << std::endl;
    }
  }

  m_ui->textEdit->setText(m_inputGenerator->fileContents("apbs.in"));
}
}
}
