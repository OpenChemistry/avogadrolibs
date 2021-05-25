/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "openmminputdialog.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>

#include <avogadro/qtgui/molecule.h>

#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QTextEdit>

#include <QtCore/QDebug>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QHash>
#include <QtCore/QPointer>
#include <QtCore/QString>
#include <QtCore/QTextStream>

namespace Avogadro {
namespace QtPlugins {

OpenMMInputDialog::OpenMMInputDialog(QWidget* parent, Qt::WindowFlags flag)
  : QDialog(parent, flag), m_molecule(nullptr),

    m_forceFieldType(amber99sbildn), m_title("Title"), m_savePath(""),
    m_waterModelType(tip3p), m_nonBondedType(PME),

    m_constraintType(HBonds), m_integratorType(Langevin),
    m_barostatType(NoBarostat),

    m_deviceIndex(1), m_openclPlatformIndex(1), m_rigidWater(0),
    m_temperature(298.15), m_generationTemperature(298.15),
    m_nonBondedCutoff(1.0),

    m_timeStep(2.0), m_ewaldTolerance(0.0005), m_constraintTolerance(0.00001),
    m_reportInterval(1000), m_equilibriationSteps(100), m_productionSteps(1000),
    m_errorTolerance(0.0001), m_collisionRate(1.0), m_pressure(1.0),
    m_barostatInterval(25),

    m_dumpStep(1),

    m_velocityDistRandom(0), m_platformType(CUDA),
    m_precisionType(mixedPrecision), m_thermoInterval(50),

    m_minimize(0), m_minimizeSteps(1000), m_DCDReporter(true),
    m_PDBReporter(false), m_stateDataReporter(true),

    m_output(), m_dirty(false), m_warned(false), readData(false),

    m_jobEdit(nullptr), m_moleculeEdit(nullptr)
{
  ui.setupUi(this);
  m_jobFileName =
    (ui.jobScriptEdit->text().isEmpty() ? ui.jobScriptEdit->placeholderText()
                                        : ui.jobScriptEdit->text()) +
    ".py";
  m_inputCoordFileName =
    (ui.inputCoordEdit->text().isEmpty() ? ui.inputCoordEdit->placeholderText()
                                         : ui.inputCoordEdit->text());
  m_topologyFileName =
    (ui.inputTopEdit->text().isEmpty() ? ui.inputTopEdit->placeholderText()
                                       : ui.inputTopEdit->text());

  // Connect the GUI elements to the correct slots
  connect(ui.jobScriptEdit, SIGNAL(textChanged(QString)), this,
          SLOT(setScriptName()));
  connect(ui.inputCoordEdit, SIGNAL(textChanged(QString)), this,
          SLOT(setInputCoordName()));
  connect(ui.forceFieldCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setForceField(int)));
  connect(ui.constraintsCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setConstraintType(int)));
  connect(ui.waterModelCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setWaterModelType(int)));
  connect(ui.nonBondedMethodCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setNonBondedType(int)));
  connect(ui.integratorCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setIntegratorType(int)));
  connect(ui.barostatCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setBarostatType(int)));
  connect(ui.inputTopEdit, SIGNAL(textChanged(QString)), this,
          SLOT(setTopologyName()));
  connect(ui.rigidWaterCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setRigidWater(int)));
  connect(ui.temperatureSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setTemperature(double)));
  connect(ui.generationTemperatureSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setGenerationTemperature(double)));
  connect(ui.nonBondedCutoffSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setNonBondedCutoff(double)));
  connect(ui.stepSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setTimeStep(double)));
  connect(ui.ewaldToleranceSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setEwaldTolerance(double)));
  connect(ui.constraintToleranceSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setConstraintTolerance(double)));
  connect(ui.reportIntervalSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setReportInterval(int)));
  connect(ui.equilibriationStepsSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setEquilibriationSteps(int)));
  connect(ui.productionStepsSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setProductionSteps(int)));
  connect(ui.deviceIndexSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setDeviceIndex(int)));
  connect(ui.openCLIndexSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setOpenCLPlatformIndex(int)));
  connect(ui.errorTolSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setErrorTolerance(double)));
  connect(ui.collisionRateSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setCollisionRate(double)));
  connect(ui.pressureSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setPressure(double)));
  connect(ui.barostatIntervalSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setBarostatInterval(int)));
  connect(ui.minimizeCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setMinimize(int)));
  connect(ui.minimizeStepsSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setMinimizeSteps(int)));
  connect(ui.initVelCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setVelocityDistRandom(int)));
  connect(ui.platformCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setPlatformType(int)));
  connect(ui.precisionCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setPrecisionType(int)));
  connect(ui.dcdCheck, SIGNAL(toggled(bool)), this, SLOT(setDCDReporter(bool)));
  connect(ui.pdbCheck, SIGNAL(toggled(bool)), this, SLOT(setPDBReporter(bool)));
  connect(ui.stateDataCheck, SIGNAL(toggled(bool)), this,
          SLOT(setStateDataReporter(bool)));

  connect(ui.stepIndexCheck, SIGNAL(toggled(bool)), this,
          SLOT(setStepIndexBoolean(bool)));
  connect(ui.timeCheck, SIGNAL(toggled(bool)), this,
          SLOT(setTimeBoolean(bool)));
  connect(ui.speedCheck, SIGNAL(toggled(bool)), this,
          SLOT(setSpeedBoolean(bool)));
  connect(ui.progressCheck, SIGNAL(toggled(bool)), this,
          SLOT(setProgressBoolean(bool)));
  connect(ui.potentialEnergyCheck, SIGNAL(toggled(bool)), this,
          SLOT(setPotentialEnergyBoolean(bool)));
  connect(ui.kineticEnergyCheck, SIGNAL(toggled(bool)), this,
          SLOT(setKineticEnergyBoolean(bool)));
  connect(ui.totalEnergyCheck, SIGNAL(toggled(bool)), this,
          SLOT(setTotalEnergyBoolean(bool)));
  connect(ui.temperatureCheck, SIGNAL(toggled(bool)), this,
          SLOT(setTemperatureBoolean(bool)));
  connect(ui.volumeCheck, SIGNAL(toggled(bool)), this,
          SLOT(setVolumeBoolean(bool)));
  connect(ui.densityCheck, SIGNAL(toggled(bool)), this,
          SLOT(setDensityBoolean(bool)));

  connect(ui.generateButton, SIGNAL(clicked()), this, SLOT(generateClicked()));
  connect(ui.resetButton, SIGNAL(clicked()), this, SLOT(resetClicked()));

  connect(ui.enableFormButton, SIGNAL(clicked()), this,
          SLOT(enableFormClicked()));

  QSettings settings;
  readSettings(settings);

  resetClicked();

  // Generate an initial preview of the input deck
  updatePreviewText();
  addMoleculeDataTab();
}

OpenMMInputDialog::~OpenMMInputDialog()
{
  QSettings settings;
  writeSettings(settings);
}

void OpenMMInputDialog::showEvent(QShowEvent*)
{
  updatePreviewText();
  addMoleculeDataTab();
}

void OpenMMInputDialog::updatePreviewText()
{
  if (!isVisible())
    return;

  int jobTabPosition = 0;

  // Store the currently displayed tab
  int currIndex = ui.tabWidget->currentIndex();

  // Generate the input deck and display it
  if (m_dirty) {
    QString message =
      tr("Would you like to update the preview text, losing all "
         "changes made in the OpenMM input deck preview pane?");
    int response = QMessageBox::question(
      this, tr("Overwrite modified input files?"), message,
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (static_cast<QMessageBox::StandardButton>(response) == QMessageBox::No) {
      return;
    }
  }

  ui.tabWidget->removeTab(jobTabPosition);

  m_jobEdit = new QTextEdit(this);
  m_jobEdit->setObjectName(m_jobFileName);
  m_jobEdit->setFontFamily("monospace");
  connect(m_jobEdit, SIGNAL(textChanged()), this, SLOT(textEditModified()));
  m_jobEdit->setText(generateInputDeck());
  ui.tabWidget->insertTab(jobTabPosition, m_jobEdit, m_jobFileName);
  deckDirty(false);

  // Restore current tab
  ui.tabWidget->setCurrentIndex(currIndex);
}

void OpenMMInputDialog::addMoleculeDataTab()
{
  int molTabPosition = 1;
  if (m_molecule) {
    ui.tabWidget->removeTab(molTabPosition);
    std::string molOutput,
      extension = m_inputCoordFileName.split(".").back().toStdString();

    bool writeSDF = Io::FileFormatManager::instance().writeString(
      *m_molecule, molOutput, extension);
    if (writeSDF) {
      m_moleculeEdit = new QTextEdit(this);
      m_moleculeEdit->setObjectName(m_inputCoordFileName);
      m_moleculeEdit->setFontFamily("monospace");
      m_moleculeEdit->setText(QString::fromStdString(molOutput));
      ui.tabWidget->insertTab(molTabPosition, m_moleculeEdit,
                              m_inputCoordFileName);
    }
  }
}

void OpenMMInputDialog::textEditModified()
{
  if (QTextEdit* edit = qobject_cast<QTextEdit*>(sender())) {
    if (edit->document()->isModified()) {
      deckDirty(true);
    } else {
      deckDirty(false);
    }
  }
}

void OpenMMInputDialog::resetClicked()
{
  // Reset the form to defaults
  deckDirty(false);

  // 1st subdivision
  ui.precisionCombo->setCurrentIndex(1);
  ui.forceFieldCombo->setCurrentIndex(2);
  ui.waterModelCombo->setCurrentIndex(1);
  ui.platformCombo->setCurrentIndex(3);
  setPlatformType(3);

  // 2nd subdivision
  ui.ewaldToleranceSpin->setValue(0.0005);
  ui.constraintToleranceSpin->setValue(0.00001);
  ui.nonBondedCutoffSpin->setValue(1.0);
  ui.generationTemperatureSpin->setValue(298.15);
  ui.nonBondedMethodCombo->setCurrentIndex(4);
  setNonBondedType(4);
  ui.constraintsCombo->setCurrentIndex(1);
  setConstraintType(1);
  ui.rigidWaterCombo->setCurrentIndex(0);
  setRigidWater(0);
  ui.initVelCombo->setCurrentIndex(0);
  setVelocityDistRandom(0);

  // 3rd subdivision
  ui.stepSpin->setValue(2.0);
  ui.errorTolSpin->setValue(0.0001);
  ui.collisionRateSpin->setValue(1.0);
  ui.temperatureSpin->setValue(298.15);
  ui.pressureSpin->setValue(1.0);
  ui.barostatIntervalSpin->setValue(25);
  ui.barostatCombo->setCurrentIndex(0);
  setBarostatType(0);
  ui.integratorCombo->setCurrentIndex(0);
  setIntegratorType(0);

  // 4th subdivision
  ui.minimizeCombo->setCurrentIndex(0);
  ui.reportIntervalSpin->setValue(1000);
  ui.minimizeStepsSpin->setValue(1000);
  ui.productionStepsSpin->setValue(1000);
  ui.equilibriationStepsSpin->setValue(100);
  ui.stepIndexCheck->setChecked(true);
  ui.timeCheck->setChecked(false);
  ui.speedCheck->setChecked(true);
  ui.progressCheck->setChecked(true);
  ui.potentialEnergyCheck->setChecked(true);
  ui.kineticEnergyCheck->setChecked(false);
  ui.totalEnergyCheck->setChecked(false);
  ui.temperatureCheck->setChecked(true);
  ui.volumeCheck->setChecked(false);
  ui.densityCheck->setChecked(false);
  // Unfortunately, setChecked() does not emit toggled() signal
  // So the slots have to be invoked
  setStepIndexBoolean(true);
  setTimeBoolean(false);
  setSpeedBoolean(true);
  setProgressBoolean(true);
  setPotentialEnergyBoolean(true);
  setKineticEnergyBoolean(false);
  setTotalEnergyBoolean(false);
  setTemperatureBoolean(true);
  setVolumeBoolean(false);
  setDensityBoolean(false);

  ui.stateDataCheck->setChecked(true);
  ui.dcdCheck->setChecked(true);
  ui.pdbCheck->setChecked(false);

  updatePreviewText();
  addMoleculeDataTab();
}

void OpenMMInputDialog::generateClicked()
{
  QSettings settings;
  QString directory =
    settings.value("openmmInput/outputDirectory", QDir::homePath()).toString();
  if (directory.isEmpty())
    directory = QDir::homePath();
  directory = QFileDialog::getExistingDirectory(
    this, tr("Select output directory"), directory);

  // User cancel:
  if (directory.isNull())
    return;

  settings.setValue("openmmInput/outputDirectory", directory);
  QDir dir(directory);

  // Check for problems:
  QStringList errors;
  bool fatalError = false;

  do { // Do/while to break on fatal errors
    if (!dir.exists()) {
      errors << tr("%1: Directory does not exist!").arg(dir.absolutePath());
      fatalError = true;
      break;
    }

    if (!dir.isReadable()) {
      errors << tr("%1: Directory cannot be read!").arg(dir.absolutePath());
      fatalError = true;
      break;
    }

    QFileInfo jobFileInfo(dir.absoluteFilePath(m_jobFileName));

    if (jobFileInfo.exists()) {
      errors << tr("%1: File will be overwritten.")
                  .arg(jobFileInfo.absoluteFilePath());
    }

    // Attempt to open the file for writing
    if (!QFile(jobFileInfo.absoluteFilePath()).open(QFile::WriteOnly)) {
      errors
        << tr("%1: File is not writable.").arg(jobFileInfo.absoluteFilePath());
      fatalError = true;
      break;
    }

    QFileInfo molFileInfo(dir.absoluteFilePath(m_inputCoordFileName));

    if (molFileInfo.exists()) {
      errors << tr("%1: File will be overwritten.")
                  .arg(molFileInfo.absoluteFilePath());
    }

    // Attempt to open the file for writing
    if (!QFile(molFileInfo.absoluteFilePath()).open(QFile::WriteOnly)) {
      errors
        << tr("%1: File is not writable.").arg(molFileInfo.absoluteFilePath());
      fatalError = true;
      break;
    }
  } while (false); // only run once

  // Handle fatal errors:
  if (fatalError) {
    QString formattedError;
    switch (errors.size()) {
      case 0:
        formattedError =
          tr("The input files cannot be written due to an unknown error.");
        break;
      case 1:
        formattedError =
          tr("The input files cannot be written:\n\n%1").arg(errors.first());
        break;
      default: {
        // If a fatal error occured, it will be last one in the list. Pop it off
        // and tell the user that it was the reason we had to stop.
        QString fatal = errors.last();
        QStringList tmp(errors);
        tmp.pop_back();
        formattedError =
          tr("The input files cannot be written:\n\n%1\n\nWarnings:\n\n%2")
            .arg(fatal, tmp.join("\n"));
        break;
      }
    }
    QMessageBox::critical(this, tr("Output Error"), formattedError);
    return;
  }

  // Non-fatal errors:
  if (!errors.isEmpty()) {
    QString formattedError = tr("Warning:\n\n%1\n\nWould you like to continue?")
                               .arg(errors.join("\n"));

    QMessageBox::StandardButton reply =
      QMessageBox::warning(this, tr("Write input files"), formattedError,
                           QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
      return;
  }

  bool success = false;

  if (m_jobEdit && m_moleculeEdit) {
    QFile jobFile(dir.absoluteFilePath(m_jobFileName));
    if (jobFile.open(QFile::WriteOnly | QFile::Text)) {
      if (jobFile.write(m_jobEdit->toPlainText().toLocal8Bit()) > 0) {
        success = true;
      }
      jobFile.close();
    }

    if (!success) {
      QMessageBox::critical(
        this, tr("Output Error"),
        tr("Failed to write to file %1.").arg(jobFile.fileName()));
    }

    QFile molFile(dir.absoluteFilePath(m_inputCoordFileName));
    if (molFile.open(QFile::WriteOnly | QFile::Text)) {
      if (molFile.write(m_moleculeEdit->toPlainText().toLocal8Bit()) > 0) {
        success = true;
      }
      molFile.close();
    }

    if (!success) {
      QMessageBox::critical(
        this, tr("Output Error"),
        tr("Failed to write to file %1.").arg(molFile.fileName()));
    }
  }
}

void OpenMMInputDialog::enableFormClicked()
{
  updatePreviewText();
}

void OpenMMInputDialog::setScriptName()
{
  m_jobFileName =
    (ui.jobScriptEdit->text().isEmpty() ? ui.jobScriptEdit->placeholderText()
                                        : ui.jobScriptEdit->text()) +
    ".py";
  updatePreviewText();
}

void OpenMMInputDialog::setInputCoordName()
{
  ui.inputCoordEdit->setStyleSheet("");
  m_inputCoordFileName =
    (ui.inputCoordEdit->text().isEmpty() ? ui.inputCoordEdit->placeholderText()
                                         : ui.inputCoordEdit->text());
  QString ext = m_inputCoordFileName.split(".").back();
  if (ext == tr("inpcrd") || ext == tr("gro")) {
    ui.forceFieldCombo->setEnabled(false);
    ui.inputTopEdit->setEnabled(true);
    if (ext == tr("inpcrd"))
      ui.inputTopEdit->setPlaceholderText(tr("input.prmtop"));
    else if (ext == tr("gro")) {
      ui.inputTopEdit->setPlaceholderText(tr("input.top"));
    }
    updatePreviewText();
  } else if (ext == tr("pdb")) {
    ui.forceFieldCombo->setEnabled(true);
    ui.inputTopEdit->setEnabled(false);
    updatePreviewText();
  } else {
    ui.forceFieldCombo->setEnabled(false);
    ui.inputTopEdit->setEnabled(false);
    ui.inputCoordEdit->setStyleSheet("color: #FF0000");
  }
  addMoleculeDataTab();
}

void OpenMMInputDialog::setTopologyName()
{
  ui.inputCoordEdit->setStyleSheet("");
  m_topologyFileName =
    (ui.inputTopEdit->text().isEmpty() ? ui.inputTopEdit->placeholderText()
                                       : ui.inputTopEdit->text());
  QString ext = m_topologyFileName.split(".").back();
  QString extCoord = m_inputCoordFileName.split(".").back();
  if (extCoord == tr("inpcrd")) {
    if (ext != tr("prmtop")) {
      ui.inputCoordEdit->setStyleSheet("color: #FF0000");
    }
  } else if (extCoord == tr("gro")) {
    if (ext != tr("top")) {
      ui.inputCoordEdit->setStyleSheet("color: #FF0000");
    }
  }
  updatePreviewText();
}

void OpenMMInputDialog::setForceField(int n)
{
  m_forceFieldType = (OpenMMInputDialog::forceFieldType)n;
  ui.forceFieldCombo->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setConstraintType(int n)
{
  m_constraintType = static_cast<OpenMMInputDialog::constraintType>(n);
  ui.constraintsCombo->setEnabled(true);
  if (m_constraintType == None) {
    ui.constraintToleranceSpin->setEnabled(false);
  } else {
    ui.constraintToleranceSpin->setEnabled(true);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setWaterModelType(int n)
{
  m_waterModelType = static_cast<OpenMMInputDialog::waterModelType>(n);
  ui.waterModelCombo->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setNonBondedType(int n)
{
  m_nonBondedType = static_cast<OpenMMInputDialog::nonBondedType>(n);
  ui.nonBondedMethodCombo->setEnabled(true);
  if (m_nonBondedType == NoCutoff) {
    ui.nonBondedCutoffSpin->setEnabled(false);
    ui.ewaldToleranceSpin->setEnabled(false);
  } else if (m_nonBondedType == CutoffPeriodic ||
             m_nonBondedType == CutoffNonPeriodic) {
    ui.nonBondedCutoffSpin->setEnabled(true);
    ui.ewaldToleranceSpin->setEnabled(false);
  } else if (m_nonBondedType == Ewald || m_nonBondedType == PME) {
    ui.nonBondedCutoffSpin->setEnabled(true);
    ui.ewaldToleranceSpin->setEnabled(true);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setIntegratorType(int n)
{
  m_integratorType = static_cast<OpenMMInputDialog::integratorType>(n);
  ui.integratorCombo->setEnabled(true);
  if (m_integratorType == Langevin || m_integratorType == Brownian ||
      m_integratorType == VariableLangevin) {
    if (m_integratorType == Langevin || m_integratorType == Brownian) {
      ui.stepSpin->setEnabled(true);
      ui.errorTolSpin->setEnabled(false);
    } else if (m_integratorType == VariableLangevin) {
      ui.stepSpin->setEnabled(false);
      ui.errorTolSpin->setEnabled(true);
    }
    ui.collisionRateSpin->setEnabled(true);
    ui.temperatureSpin->setEnabled(true);
    ui.barostatCombo->setEnabled(true);
    if (m_barostatType == NoBarostat) {
      ui.pressureSpin->setEnabled(false);
      ui.barostatIntervalSpin->setEnabled(false);
    } else {
      ui.pressureSpin->setEnabled(true);
      ui.barostatIntervalSpin->setEnabled(true);
    }
  } else if (m_integratorType == Verlet || m_integratorType == VariableVerlet) {
    if (m_integratorType == Verlet) {
      ui.stepSpin->setEnabled(true);
      ui.errorTolSpin->setEnabled(false);
    } else if (m_integratorType == VariableVerlet) {
      ui.stepSpin->setEnabled(false);
      ui.errorTolSpin->setEnabled(true);
    }
    ui.collisionRateSpin->setEnabled(false);
    ui.temperatureSpin->setEnabled(false);
    ui.barostatCombo->setEnabled(false);
    ui.pressureSpin->setEnabled(false);
    ui.barostatIntervalSpin->setEnabled(false);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setBarostatType(int n)
{
  m_barostatType = static_cast<OpenMMInputDialog::barostatType>(n);
  ui.barostatCombo->setEnabled(true);
  if (m_barostatType == NoBarostat) {
    ui.pressureSpin->setEnabled(false);
    ui.barostatIntervalSpin->setEnabled(false);
  } else {
    ui.pressureSpin->setEnabled(true);
    ui.barostatIntervalSpin->setEnabled(true);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setMolecule(QtGui::Molecule* molecule)
{
  // Disconnect the old molecule first...
  if (molecule == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = molecule;
  // Update the preview text whenever primitives are changed
  connect(molecule, SIGNAL(changed(unsigned int)), SLOT(updatePreviewText()));
  updatePreviewText();
}

void OpenMMInputDialog::setRigidWater(int n)
{
  m_rigidWater = n;
  ui.rigidWaterCombo->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setMinimize(int n)
{
  m_minimize = n;
  ui.minimizeCombo->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setMinimizeSteps(int n)
{
  m_minimizeSteps = n;
  ui.minimizeStepsSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setTemperature(double n)
{
  m_temperature = n;
  ui.temperatureSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setNonBondedCutoff(double n)
{
  m_nonBondedCutoff = n;
  ui.nonBondedCutoffSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setTimeStep(double n)
{
  m_timeStep = n;
  ui.stepSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setEwaldTolerance(double n)
{
  m_ewaldTolerance = n;
  ui.ewaldToleranceSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setConstraintTolerance(double n)
{
  m_constraintTolerance = n;
  ui.constraintToleranceSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setReportInterval(int n)
{
  m_reportInterval = n;
  ui.reportIntervalSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setEquilibriationSteps(int n)
{
  m_equilibriationSteps = n;
  ui.equilibriationStepsSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setProductionSteps(int n)
{
  m_productionSteps = n;
  ui.productionStepsSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setDeviceIndex(int n)
{
  m_deviceIndex = n;
  ui.deviceIndexSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setOpenCLPlatformIndex(int n)
{
  m_openclPlatformIndex = n;
  ui.openCLIndexSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setErrorTolerance(double n)
{
  m_errorTolerance = n;
  ui.errorTolSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setCollisionRate(double n)
{
  m_collisionRate = n;
  ui.collisionRateSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setPressure(double n)
{
  m_pressure = n;
  ui.pressureSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setBarostatInterval(int n)
{
  m_barostatInterval = n;
  ui.barostatIntervalSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setVelocityDistRandom(int n)
{
  m_velocityDistRandom = n;
  ui.initVelCombo->setEnabled(true);
  if (m_velocityDistRandom == 1) {
    ui.generationTemperatureSpin->setEnabled(false);
  } else {
    ui.generationTemperatureSpin->setEnabled(true);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setGenerationTemperature(double n)
{
  m_generationTemperature = n;
  ui.generationTemperatureSpin->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setDCDReporter(bool state)
{
  m_DCDReporter = state;
  ui.dcdCheck->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setPDBReporter(bool state)
{
  m_PDBReporter = state;
  ui.pdbCheck->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setStepIndexBoolean(bool state)
{
  m_stepIndex = state;
  ui.stepIndexCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setTimeBoolean(bool state)
{
  m_time = state;
  ui.timeCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setSpeedBoolean(bool state)
{
  m_speed = state;
  ui.speedCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setProgressBoolean(bool state)
{
  m_progress = state;
  ui.progressCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setPotentialEnergyBoolean(bool state)
{
  m_potentialEnergy = state;
  ui.potentialEnergyCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setKineticEnergyBoolean(bool state)
{
  m_kineticEnergy = state;
  ui.kineticEnergyCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setTotalEnergyBoolean(bool state)
{
  m_totalEnergy = state;
  ui.totalEnergyCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setTemperatureBoolean(bool state)
{
  m_temperature = state;
  ui.temperatureCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setVolumeBoolean(bool state)
{
  m_volume = state;
  ui.volumeCheck->setEnabled(true);
  updatePreviewText();
}
void OpenMMInputDialog::setDensityBoolean(bool state)
{
  m_density = state;
  ui.densityCheck->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setStateDataReporter(bool state)
{
  ui.stepIndexCheck->setEnabled(state);
  ui.timeCheck->setEnabled(state);
  ui.speedCheck->setEnabled(state);
  ui.progressCheck->setEnabled(state);
  ui.potentialEnergyCheck->setEnabled(state);
  ui.kineticEnergyCheck->setEnabled(state);
  ui.totalEnergyCheck->setEnabled(state);
  ui.temperatureCheck->setEnabled(state);
  ui.volumeCheck->setEnabled(state);
  ui.densityCheck->setEnabled(state);

  m_stateDataReporter = state;
  ui.stateDataCheck->setEnabled(true);
  updatePreviewText();
}

void OpenMMInputDialog::setPlatformType(int n)
{
  m_platformType = static_cast<OpenMMInputDialog::platformType>(n);
  ui.platformCombo->setEnabled(true);
  if (m_platformType == Reference || m_platformType == CPU) {
    ui.precisionCombo->setEnabled(false);
    ui.deviceIndexSpin->setEnabled(false);
    ui.openCLIndexSpin->setEnabled(false);
  } else {
    ui.precisionCombo->setEnabled(true);
    ui.deviceIndexSpin->setEnabled(true);
    if (m_platformType == OpenCL)
      ui.openCLIndexSpin->setEnabled(true);
    else
      ui.openCLIndexSpin->setEnabled(false);
  }
  updatePreviewText();
}

void OpenMMInputDialog::setPrecisionType(int n)
{
  m_precisionType = static_cast<OpenMMInputDialog::precisionType>(n);
  ui.precisionCombo->setEnabled(true);
  updatePreviewText();
}

QString OpenMMInputDialog::generateInputDeck()
{
  // Generate an input deck based on the settings of the dialog
  QString buffer;
  QTextStream scriptStream(&buffer);

  scriptStream << "############################################################"
                  "##############\n";
  scriptStream << "# OpenMM input script generated by Avogadro.\n";
  scriptStream << "# Builder adapted from OpenMM script builder "
                  "http://builder.openmm.org.\n";
  scriptStream << "############################################################"
                  "##############\n\n";
  scriptStream << "from __future__ import print_function\n";
  scriptStream << "from simtk.openmm import app\n";
  scriptStream << "import simtk.openmm as mm\n";
  scriptStream << "from simtk import unit\n";
  scriptStream << "from sys import stdout\n";

  // first two or three lines, that load up the FF and the pdb
  // these lines end with the start of the function something.createSystem(
  QString ext = m_inputCoordFileName.split(".").back();
  if (ext == tr("pdb")) {
    scriptStream << "\npdb = app.PDBFile(\'" << m_inputCoordFileName << "\')\n";
    scriptStream << "forcefield = app.ForceField(\'"
                 << getForceFieldType(m_forceFieldType) << ".xml\'";
    scriptStream << ", \'" << getWaterModelType(m_waterModelType) << ".xml\'";
    scriptStream << ")\n\n";
    scriptStream << "system = forcefield.createSystem(pdb.topology, ";
  } else if (ext == tr("inpcrd")) {
    scriptStream << "\nprmtop = app.AmberPrmtopFile(\'" << m_topologyFileName
                 << "\')\n";
    scriptStream << "inpcrd = app.AmberInpcrdFile(\'" << m_inputCoordFileName
                 << "\')\n\n";
    scriptStream << "system = prmtop.createSystem(";
    if (m_waterModelType == implicit) {
      scriptStream << "implicitSolvent=app.OBC2, ";
    }
  } else if (ext == tr("gro")) {
    scriptStream << "\ngro = app.GromacsGroFile(\'" << m_inputCoordFileName
                 << "\')\n";
    scriptStream << "top = app.GromacsTopFile(\'" << m_topologyFileName
                 << "\')\n\n";
    scriptStream << "system = top.createSystem(";
    if (m_waterModelType == implicit) {
      scriptStream << "implicitSolvent=app.OBC2, ";
    }
  } else {
    // TODO
  }

  // options for the system
  scriptStream << "nonbondedMethod="
               << "app." << getNonBondedType(m_nonBondedType) << ",";
  if (m_nonBondedCutoff > 0) {
    scriptStream << " nonbondedCutoff=" << fixed << qSetRealNumberPrecision(4)
                 << m_nonBondedCutoff << "*unit.nanometers,";
  }
  if (m_constraintType == None) {
    scriptStream << " constraints=" << getConstraintType(m_constraintType);
  } else {
    scriptStream << " constraints="
                 << "app." << getConstraintType(m_constraintType);
  }
  scriptStream << ", rigidWater=" << getRigidWater(m_rigidWater);
  if (m_nonBondedType == Ewald || m_nonBondedType == PME) {
    scriptStream << ", ewaldErrorTolerance=" << fixed
                 << qSetRealNumberPrecision(5) << m_ewaldTolerance;
  }
  scriptStream << ")\n";

  // set the integrator
  scriptStream << "integrator = mm." << getIntegratorType(m_integratorType)
               << "Integrator(";
  if (m_integratorType == Langevin || m_integratorType == Brownian) {
    scriptStream << m_temperature << "*unit.kelvin, ";
    scriptStream << m_collisionRate << "/unit.picoseconds, ";
  }
  if (m_integratorType == VariableLangevin ||
      m_integratorType == VariableVerlet) {
    scriptStream << m_errorTolerance << ")\n";
  } else {
    scriptStream << m_timeStep << "*unit.femtoseconds)\n";
  }
  if (m_constraintType != None && m_constraintTolerance > 0) {
    scriptStream << "integrator.setConstraintTolerance("
                 << m_constraintTolerance << ")\n";
  }

  // add a barostat
  if (m_barostatType == MonteCarlo) {
    scriptStream << "system.addForce(mm.MonteCarloBarostat(" << m_pressure
                 << "*unit.atmospheres";
    scriptStream << ", " << m_temperature << "*unit.kelvin";
    if (m_barostatInterval > 0) {
      scriptStream << ", " << m_barostatInterval;
    }
    scriptStream << "))\n";
  }

  // // add a thermostat
  // if (m_thermostatType == Andersen) {
  //     scriptStream << "system.addForce(mm.AndersenThermostat(" <<
  //     m_temperature << "*unit.kelvin"; scriptStream << ", " <<
  //     m_collisionRate << "/unit.picoseconds" << "))\n";
  // }

  scriptStream << "\n";

  // set the platform options
  scriptStream << "platform = mm.Platform.getPlatformByName(\'"
               << getPlatformType(m_platformType) << "\')\n";
  if (m_platformType == CUDA) {
    scriptStream << "properties = {\'CudaPrecision\': \'"
                 << getPrecisionType(m_precisionType) << "\'";
    if (m_deviceIndex > 0) {
      scriptStream << ", \'CudaDeviceIndex\': \'" << m_deviceIndex << "\'";
    }
    scriptStream << "}\n";
  } else if (m_platformType == OpenCL) {
    scriptStream << "properties = {\'OpenCLPrecision\': \'"
                 << getPrecisionType(m_precisionType) << "\'";
    if (m_openclPlatformIndex > 0) {
      scriptStream << ", \'OpenCLPlatformIndex\': \'" << m_openclPlatformIndex
                   << "\'";
    }
    if (m_deviceIndex > 0) {
      scriptStream << ", ";
      if (m_openclPlatformIndex > 0) {
        scriptStream << "\n              ";
      }
      scriptStream << "\'OpenCLDeviceIndex\': \'" << m_deviceIndex << "\'";
    }
    scriptStream << "}\n";
  }

  // create the simulation object
  scriptStream << "simulation = app.Simulation("
               << (ext == tr("pdb") ? "pdb" : "prmtop")
               << ".topology, system, integrator, platform";
  if (m_platformType == CUDA || m_platformType == OpenCL) {
    scriptStream << ", properties";
  }
  scriptStream << ")\n";

  if (ext == tr("pdb")) {
    scriptStream << "simulation.context.setPositions(pdb.positions)\n\n";
  } else if (ext == tr("inpcrd")) {
    scriptStream << "simulation.context.setPositions(inpcrd.positions)\n\n";
  } else if (ext == tr("gro")) {
    scriptStream << "simulation.context.setPositions(gro.positions)\n\n";
  } else {
    // TODO
  }

  // minimize
  if (getMinimize(m_minimize) == tr("True")) {
    scriptStream << "print('Minimizing...\')\n";
    if (m_minimizeSteps == 0) {
      scriptStream << "simulation.minimizeEnergy()\n";
    } else {
      scriptStream << "simulation.minimizeEnergy(maxIterations="
                   << m_minimizeSteps << ")\n";
    }
  }
  if (getVelocityDistRandom(m_velocityDistRandom) == tr("True")) {
    scriptStream << "\nsimulation.context.setVelocitiesToTemperature("
                 << m_generationTemperature << "*unit.kelvin)\n";
  }

  // equilibrate
  if (m_equilibriationSteps > 0) {
    scriptStream << "print(\'Equilibrating...\')\n";
    scriptStream << "simulation.step(" << m_equilibriationSteps << ")\n\n";
  }

  // add reporters
  // if (d.simulation.dcd_reporter == 'True' &&
  // d.simulation.statedata_opts.length > 0) {
  if (m_DCDReporter) {
    scriptStream
      << "simulation.reporters.append(app.DCDReporter(\'trajectory.dcd\'";
    scriptStream << ", " << m_reportInterval << "))\n";
    scriptStream << "\n";
  }
  if (m_PDBReporter) {
    scriptStream
      << "simulation.reporters.append(app.PDBReporter(\'trajectory.pdb\'";
    scriptStream << ", " << m_reportInterval << "))\n";
    scriptStream << "\n";
  }
  if (m_stateDataReporter) {
    scriptStream << "simulation.reporters.append(app.StateDataReporter(";
    scriptStream << "stdout";
    scriptStream << ", " << m_reportInterval;
    if (m_stepIndex)
      scriptStream << ", step=True";
    if (m_time)
      scriptStream << ", time=True";
    if (m_potentialEnergy)
      scriptStream << ", potentialEnergy=True";
    if (m_kineticEnergy)
      scriptStream << ", kineticEnergy=True";
    if (m_totalEnergy)
      scriptStream << ", totalEnergy=True";
    if (m_temperatureCheck)
      scriptStream << ", temperature=True";
    if (m_volume)
      scriptStream << ", volume=True";
    if (m_density)
      scriptStream << ", density=True";
    if (m_progress)
      scriptStream << ", progress=True, remainingTime=True";
    if (m_speed)
      scriptStream << ", speed=True";
    // if using progress (which also implies remaining time), totalSteps
    // is required.
    if (m_progress)
      scriptStream << ", totalSteps=" << m_productionSteps;
    scriptStream << ", separator=\'\\t\'))\n";
    scriptStream << "\n";
  }

  // run
  scriptStream << "print(\'Running Production...\')\n";
  scriptStream << "simulation.step(" << m_productionSteps << ")\n";
  scriptStream << "print(\'Done!\')\n";

  return buffer;
}

QString OpenMMInputDialog::getForceFieldType(forceFieldType t)
{
  // Translate the enum to text for the output generation
  switch (t) {
    case amber96:
      return "amber96";
    case amber99sb:
      return "amber99sb";
    case amber99sbildn:
      return "amber99sbildn";
    case amber99sbnmr:
      return "amber99sbnmr";
    case amber03:
      return "amber03";
    case amber10:
      return "amber10";
    default:
      return "amber99sbildn";
  }
}

QString OpenMMInputDialog::getImplicitSolventType(forceFieldType t)
{
  // Translate the enum to text for the output generation
  switch (t) {
    case amber96:
      return "amber96_obc";
    case amber99sb:
      return "amber99_obc";
    case amber99sbildn:
      return "amber99_obc";
    case amber99sbnmr:
      return "amber99_obc";
    case amber03:
      return "amber03_obc";
    case amber10:
      return "amber10_obc";
    default:
      return "amber99_obc";
  }
}

QString OpenMMInputDialog::getConstraintType(constraintType t)
{
  switch (t) {
    case None:
      return "None";
    case HBonds:
      return "HBonds";
    case AllBonds:
      return "AllBonds";
    case HAngles:
      return "HAngles";
    default:
      return "HBonds";
  }
}

QString OpenMMInputDialog::getWaterModelType(waterModelType t)
{
  switch (t) {
    case spce:
      return "spce";
    case tip3p:
      return "tip3p";
    case tip4pew:
      return "tip4pew";
    case tip5p:
      return "tip5p";
    case implicit:
      return getImplicitSolventType(m_forceFieldType);
    default:
      return "tip3p";
  }
}

QString OpenMMInputDialog::getNonBondedType(nonBondedType t)
{
  switch (t) {
    case NoCutoff:
      return "NoCutoff";
    case CutoffNonPeriodic:
      return "CutoffNonPeriodic";
    case CutoffPeriodic:
      return "CutoffPeriodic";
    case Ewald:
      return "Ewald";
    case PME:
      return "PME";
    default:
      return "PME";
  }
}

QString OpenMMInputDialog::getIntegratorType(integratorType t)
{
  switch (t) {
    case Langevin:
      return "Langevin";
    case Verlet:
      return "Verlet";
    case Brownian:
      return "Brownian";
    case VariableVerlet:
      return "VariableVerlet";
    case VariableLangevin:
      return "VariableLangevin";
    default:
      return "Langevin";
  }
}

QString OpenMMInputDialog::getBarostatType(barostatType t)
{
  switch (t) {
    case NoBarostat:
      return "None";
    case MonteCarlo:
      return "MonteCarlo";
    default:
      return "None";
  }
}

QString OpenMMInputDialog::getRigidWater(int t)
{
  switch (t) {
    case 0:
      return "True";
    case 1:
      return "False";
    default:
      return "False";
  }
}

QString OpenMMInputDialog::getVelocityDistRandom(int t)
{
  switch (t) {
    case 0:
      return "True";
    case 1:
      return "False";
    default:
      return "True";
  }
}

QString OpenMMInputDialog::getPlatformType(platformType t)
{
  switch (t) {
    case Reference:
      return "Reference";
    case OpenCL:
      return "OpenCL";
    case CUDA:
      return "CUDA";
    case CPU:
      return "CPU";
    default:
      return "CUDA";
  }
}

QString OpenMMInputDialog::getPrecisionType(precisionType t)
{
  switch (t) {
    case singlePrecision:
      return "single";
    case mixedPrecision:
      return "mixed";
    case doublePrecision:
      return "double";
    default:
      return "mixed";
  }
}

QString OpenMMInputDialog::getMinimize(int t)
{
  switch (t) {
    case 0:
      return "True";
    case 1:
      return "False";
    default:
      return "True";
  }
}

void OpenMMInputDialog::deckDirty(bool dirty)
{
  m_dirty = dirty;
  // ui.titleLine->setEnabled(!dirty);
  // ui.calculationCombo->setEnabled(!dirty);
  // ui.theoryCombo->setEnabled(!dirty);
  // ui.basisCombo->setEnabled(!dirty);
  // ui.multiplicitySpin->setEnabled(!dirty);
  // ui.chargeSpin->setEnabled(!dirty);
  ui.enableFormButton->setEnabled(dirty);
}

void OpenMMInputDialog::readSettings(QSettings& settings)
{
  m_savePath = settings.value("openmm/savepath").toString();
}

void OpenMMInputDialog::writeSettings(QSettings& settings) const
{
  settings.setValue("openmm/savepath", m_savePath);
}

} // namespace QtPlugins
} // namespace Avogadro
