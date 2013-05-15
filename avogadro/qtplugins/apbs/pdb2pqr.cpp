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

#include "pdb2pqr.h"
#include "ui_pdb2pqr.h"

#include <QFile>
#include <QProcess>
#include <QFileDialog>
#include <QMessageBox>

namespace Avogadro {
namespace QtPlugins {

Pdb2Pqr::Pdb2Pqr(QWidget *parent_)
  : QDialog(parent_),
    m_ui(new Ui::Pdb2Pqr)
{
  m_ui->setupUi(this);
  connect(m_ui->runButton, SIGNAL(clicked()), this, SLOT(onRunClicked()));
  connect(m_ui->cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
  connect(m_ui->inputFileNameButton, SIGNAL(clicked()),
          this, SLOT(onOpenInputFile()));
}

Pdb2Pqr::~Pdb2Pqr()
{
  delete m_ui;
}

QString Pdb2Pqr::errorString() const
{
  return m_errorString;
}

void Pdb2Pqr::onRunClicked()
{
  QString inputFileName = m_ui->inputFileNameLineEdit->text();
  QString suggestedOutputFileName =
    QFileInfo(inputFileName).baseName() + ".pqr";

  QString outputFileName =
    QFileDialog::getSaveFileName(
      this, tr("Output PQR File Name"), suggestedOutputFileName,
      tr("PQR Files (*.pqr)"));
  if (outputFileName.isEmpty())
    return;

  QString forceFieldName = m_ui->forceFieldComboBox->currentText();

  // run pdb2pqr
  QStringList arguments;
  arguments.append("--ff");
  arguments.append(forceFieldName);
  arguments.append(inputFileName);
  arguments.append(outputFileName);

  QProcess process;
  process.start("pdb2pqr", arguments);

  process.waitForFinished();

  if (process.exitStatus() == QProcess::NormalExit) {
    QMessageBox::information(
      this, "Success", QString("Generated %1").arg(outputFileName));
  }
  else {
    QMessageBox::critical(
      this, "Error", QString("Error running PDB2PQR"));
  }

  accept();
}

void Pdb2Pqr::onOpenInputFile()
{
  QString inputFileName =
    QFileDialog::getOpenFileName(
      this, tr("Input PDB File Name"), QString(), tr("PDB Files (*.pdb)"));
  if (inputFileName.isEmpty())
    return;

  m_ui->inputFileNameLineEdit->setText(inputFileName);
}

}
}
