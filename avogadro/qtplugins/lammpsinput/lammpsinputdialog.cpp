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

#include "lammpsinputdialog.h"

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

LammpsInputDialog::LammpsInputDialog(QWidget* parent, Qt::WindowFlags flag)
  : QDialog(parent, flag), m_molecule(nullptr),

    m_unitType(real), m_title("Title"), m_savePath(""), m_dimensionType(d3),
    m_xBoundaryType(p), m_yBoundaryType(p), m_zBoundaryType(p),

    m_atomStyle(full),

    m_waterPotential(NONE),

    m_ensemble(NVT), m_temperature(298.15), m_nhChain(1),

    m_timeStep(2.0), m_runSteps(50), m_xReplicate(1), m_yReplicate(1),
    m_zReplicate(1),

    m_dumpStep(1),

    m_velocityDist(gaussian), m_velocityTemp(298.15), m_zeroMOM(true),
    m_zeroL(true), m_thermoStyle(one), m_thermoInterval(50),

    m_output(), m_dirty(false), m_warned(false), readData(false),

    m_jobEdit(nullptr), m_moleculeEdit(nullptr)
{
  ui.setupUi(this);
  // Connect the GUI elements to the correct slots
  connect(ui.titleLine, SIGNAL(editingFinished()), this, SLOT(setTitle()));

  // now for something useful
  connect(ui.unitsCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setUnits(int)));
  connect(ui.atomStyleCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setAtomStyle(int)));
  connect(ui.dimensionCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setDimensionType(int)));
  connect(ui.xBoundaryCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setXBoundaryType(int)));
  connect(ui.yBoundaryCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setYBoundaryType(int)));
  connect(ui.zBoundaryCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setZBoundaryType(int)));
  connect(ui.waterPotentialCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setWaterPotential(int)));
  connect(ui.readDataLine, SIGNAL(editingFinished()), this,
          SLOT(setReadData()));
  connect(ui.ensembleCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setEnsemble(int)));
  connect(ui.tempSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setTemperature(double)));
  connect(ui.nhChainSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setNHChain(int)));
  connect(ui.stepSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setTimeStep(double)));
  connect(ui.runSpin, SIGNAL(valueChanged(int)), this, SLOT(setRunSteps(int)));
  connect(ui.xReplicateSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setXReplicate(int)));
  connect(ui.yReplicateSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setYReplicate(int)));
  connect(ui.zReplicateSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setZReplicate(int)));
  connect(ui.dumpXYZEdit, SIGNAL(editingFinished()), this, SLOT(setDumpXYZ()));
  connect(ui.dumpStepSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setDumpStep(int)));
  connect(ui.velocityDistCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setVelocityDist(int)));
  connect(ui.velocityTempSpin, SIGNAL(valueChanged(double)), this,
          SLOT(setVelocityTemp(double)));
  connect(ui.zeroMOMCheck, SIGNAL(toggled(bool)), this, SLOT(setZeroMOM(bool)));
  connect(ui.zeroLCheck, SIGNAL(toggled(bool)), this, SLOT(setZeroL(bool)));
  connect(ui.thermoStyleCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(setThermoStyle(int)));
  connect(ui.thermoSpin, SIGNAL(valueChanged(int)), this,
          SLOT(setThermoInterval(int)));

  connect(ui.generateButton, SIGNAL(clicked()), this, SLOT(generateClicked()));
  connect(ui.resetButton, SIGNAL(clicked()), this, SLOT(resetClicked()));

  connect(ui.enableFormButton, SIGNAL(clicked()), this,
          SLOT(enableFormClicked()));

  QSettings settings;
  readSettings(settings);

  // Generate an initial preview of the input deck
  updatePreviewText();
  addMoleculeDataTab();
}

LammpsInputDialog::~LammpsInputDialog()
{
  QSettings settings;
  writeSettings(settings);
}

void LammpsInputDialog::showEvent(QShowEvent*)
{
  updatePreviewText();
  addMoleculeDataTab();
}

void LammpsInputDialog::updatePreviewText()
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
         "changes made in the Lammps input deck preview pane?");
    int response = QMessageBox::question(
      this, tr("Overwrite modified input files?"), message,
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (static_cast<QMessageBox::StandardButton>(response) == QMessageBox::No) {
      return;
    }
  }

  ui.tabWidget->removeTab(jobTabPosition);

  m_jobFileName =
    (ui.baseNameEdit->text().isEmpty() ? ui.baseNameEdit->placeholderText()
                                       : ui.baseNameEdit->text()) +
    ".lmp";
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

void LammpsInputDialog::addMoleculeDataTab()
{
  int molTabPosition = 1;
  if (m_molecule) {
    ui.tabWidget->removeTab(molTabPosition);
    std::string molOutput, extension = "lmpdat";
    m_moleculeFileName =
      (ui.baseNameEdit->text().isEmpty() ? ui.baseNameEdit->placeholderText()
                                         : ui.baseNameEdit->text()) +
      "." + QString::fromStdString(extension);
    bool writeSDF = Io::FileFormatManager::instance().writeString(
      *m_molecule, molOutput, extension);
    if (writeSDF) {
      m_moleculeEdit = new QTextEdit(this);
      m_moleculeEdit->setObjectName(m_moleculeFileName);
      m_moleculeEdit->setFontFamily("monospace");
      m_moleculeEdit->setText(QString::fromStdString(molOutput));
      ui.tabWidget->insertTab(molTabPosition, m_moleculeEdit,
                              m_moleculeFileName);
    }
  }
}

void LammpsInputDialog::textEditModified()
{
  if (QTextEdit* edit = qobject_cast<QTextEdit*>(sender())) {
    if (edit->document()->isModified()) {
      deckDirty(true);
    } else {
      deckDirty(false);
    }
  }
}

void LammpsInputDialog::resetClicked()
{
  // Reset the form to defaults
  deckDirty(false);

  ui.unitsCombo->setCurrentIndex(1);
  ui.atomStyleCombo->setCurrentIndex(7);
  ui.dimensionCombo->setCurrentIndex(1);
  ui.xBoundaryCombo->setCurrentIndex(0);
  ui.yBoundaryCombo->setCurrentIndex(0);
  ui.zBoundaryCombo->setCurrentIndex(0);
  ui.waterPotentialCombo->setCurrentIndex(0);
  ui.ensembleCombo->setCurrentIndex(0);
  ui.tempSpin->setValue(298.15);
  ui.nhChainSpin->setValue(1);
  ui.stepSpin->setValue(2.0);
  ui.runSpin->setValue(50);
  ui.xReplicateSpin->setValue(1);
  ui.yReplicateSpin->setValue(1);
  ui.zReplicateSpin->setValue(1);
  ui.dumpStepSpin->setValue(1);
  ui.thermoStyleCombo->setCurrentIndex(0);
  ui.thermoSpin->setValue(50);

  updatePreviewText();
  addMoleculeDataTab();
}

void LammpsInputDialog::generateClicked()
{
  QSettings settings;
  QString directory =
    settings.value("lammpsInput/outputDirectory", QDir::homePath()).toString();
  if (directory.isEmpty())
    directory = QDir::homePath();
  directory = QFileDialog::getExistingDirectory(
    this, tr("Select output directory"), directory);

  // User cancel:
  if (directory.isNull())
    return;

  settings.setValue("lammpsInput/outputDirectory", directory);
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

    QFileInfo molFileInfo(dir.absoluteFilePath(m_moleculeFileName));

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
        // If a fatal error occurred, it will be last one in the list. Pop it off
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

    QFile molFile(dir.absoluteFilePath(m_moleculeFileName));
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

void LammpsInputDialog::enableFormClicked()
{
  updatePreviewText();
}

void LammpsInputDialog::setTitle()
{
  m_title = ui.titleLine->text();
  updatePreviewText();
}

void LammpsInputDialog::setUnits(int n)
{
  m_unitType = (LammpsInputDialog::unitType)n;
  ui.unitsCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setAtomStyle(int n)
{
  m_atomStyle = (LammpsInputDialog::atomStyle)n;
  ui.atomStyleCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setDimensionType(int n)
{
  m_dimensionType = static_cast<LammpsInputDialog::dimensionType>(n);
  ui.dimensionCombo->setEnabled(true);
  if (n == 0) {
    setZBoundaryType(0);
    ui.zBoundaryCombo->setCurrentIndex(0);
    ui.zBoundaryCombo->setEnabled(false);
    ui.zReplicateSpin->setValue(1);
    ui.zReplicateSpin->setEnabled(false);
  }
  if (n == 1) {
    ui.zBoundaryCombo->setEnabled(true);
    ui.zReplicateSpin->setEnabled(true);
  }
  updatePreviewText();
}

void LammpsInputDialog::setXBoundaryType(int n)
{
  m_xBoundaryType = static_cast<LammpsInputDialog::boundaryType>(n);
  ui.xBoundaryCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setYBoundaryType(int n)
{
  m_yBoundaryType = static_cast<LammpsInputDialog::boundaryType>(n);
  ui.yBoundaryCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setZBoundaryType(int n)
{
  m_zBoundaryType = static_cast<LammpsInputDialog::boundaryType>(n);
  // should be careful here
  // z boundary must be p for 2d!!!
  ui.zBoundaryCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setWaterPotential(int n)
{
  m_waterPotential = static_cast<LammpsInputDialog::waterPotential>(n);
  ui.waterPotentialCombo->setEnabled(true);
  if (n == 1) {
    setAtomStyle(7);
    ui.atomStyleCombo->setCurrentIndex(7);
    ui.atomStyleCombo->setEnabled(false);
  }
  if (n == 0) {
    ui.atomStyleCombo->setEnabled(true);
  }
  updatePreviewText();
}

void LammpsInputDialog::setReadData()
{
  m_readData = ui.readDataLine->text();
  if (m_readData != "")
    readData = true;
  else
    readData = false;
  updatePreviewText();
}

void LammpsInputDialog::setMolecule(QtGui::Molecule* molecule)
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

void LammpsInputDialog::setEnsemble(int n)
{
  m_ensemble = static_cast<LammpsInputDialog::ensemble>(n);
  ui.ensembleCombo->setEnabled(true);
  if (n == 1) {
    ui.tempSpin->setValue(0.0);
    ui.tempSpin->setEnabled(false);
    ui.nhChainSpin->setValue(0);
    ui.nhChainSpin->setEnabled(false);
  } else if (n == 0) {
    ui.tempSpin->setEnabled(true);
    ui.nhChainSpin->setEnabled(true);
    ui.nhChainSpin->setValue(1);
  }
  updatePreviewText();
}

void LammpsInputDialog::setTemperature(double n)
{
  m_temperature = n;
  ui.tempSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setNHChain(int n)
{
  m_nhChain = n;
  ui.nhChainSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setTimeStep(double n)
{
  m_timeStep = n;
  ui.stepSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setRunSteps(int n)
{
  m_runSteps = n;
  ui.runSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setXReplicate(int n)
{
  m_xReplicate = n;
  ui.xReplicateSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setYReplicate(int n)
{
  m_yReplicate = n;
  ui.yReplicateSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setZReplicate(int n)
{
  m_zReplicate = n;
  ui.zReplicateSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setDumpStep(int n)
{
  m_dumpStep = n;
  ui.dumpStepSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setDumpXYZ()
{
  m_dumpXYZ = ui.dumpXYZEdit->text();
  updatePreviewText();
}

void LammpsInputDialog::setVelocityDist(int n)
{
  m_velocityDist = static_cast<LammpsInputDialog::velocityDist>(n);
  ui.velocityDistCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setVelocityTemp(double n)
{
  m_velocityTemp = n;
  ui.velocityTempSpin->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setZeroMOM(bool state)
{
  m_zeroMOM = state;
  ui.zeroMOMCheck->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setZeroL(bool state)
{
  m_zeroL = state;
  ui.zeroLCheck->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setThermoStyle(int n)
{
  m_thermoStyle = static_cast<LammpsInputDialog::thermoStyle>(n);
  ui.thermoStyleCombo->setEnabled(true);
  updatePreviewText();
}

void LammpsInputDialog::setThermoInterval(int n)
{
  m_thermoInterval = n;
  ui.thermoSpin->setEnabled(true);
  updatePreviewText();
}

QString LammpsInputDialog::generateInputDeck()
{
  // Generate an input deck based on the settings of the dialog
  QString buffer;
  QTextStream mol(&buffer);

  mol << "# LAMMPS Input file generated by Avogadro\n";
  mol << "# " << m_title << "\n\n";

  mol << "# Initialization\n";
  mol << "units          " << getUnitType(m_unitType) << "\n";
  mol << "dimension      " << getDimensionType(m_dimensionType) << "\n";
  mol << "boundary       " << getXBoundaryType(m_xBoundaryType) << " "
      << getYBoundaryType(m_yBoundaryType) << " "
      << getZBoundaryType(m_zBoundaryType) << "\n";
  mol << "atom_style     " << getAtomStyle(m_atomStyle) << "\n";
  mol << "\n";

  mol << "# Atom Definition\n";
  if (readData)
    mol << "read_data      " << m_readData << "\n";
  mol << "replicate      " << m_xReplicate << " " << m_yReplicate << " "
      << m_zReplicate << "\n";

  mol << "\n" << getWaterPotential(m_waterPotential) << "\n";

  mol << "# Settings\n";
  mol << "velocity       all create " << fixed << qSetRealNumberPrecision(2)
      << m_velocityTemp << " "
      << "4928459 "
      << "rot " << getZeroL() << " "
      << "mom " << getZeroMOM() << " "
      << "dist " << getVelocityDist(m_velocityDist) << "\n";
  mol << getEnsemble(m_ensemble) << "\n";
  mol << "timestep       " << fixed << qSetRealNumberPrecision(1) << m_timeStep
      << "\n";
  mol << "\n";

  mol << "# Output\n";
  if (m_dumpXYZ != "") {
    mol << "dump           dumpXYZ all xyz " << m_dumpStep << " " << m_dumpXYZ
        << "\n";
  }
  mol << "thermo_style   " << getThermoStyle(m_thermoStyle) << "\n";
  mol << "thermo         " << m_thermoInterval << "\n";
  mol << "\n";

  mol << "# Run the simulation\n";
  mol << "run            " << m_runSteps << "\n";
  mol << "\n";

  return buffer;
}

QString LammpsInputDialog::getUnitType(unitType t)
{
  // Translate the enum to text for the output generation
  switch (t) {
    case lj:
      return "lj";
    case real:
      return "real";
    case metal:
      return "metal";
    case si:
      return "si";
    case cgs:
      return "cgs";
    case u_electron:
      return "electron";
    default:
      return "lj";
  }
}

QString LammpsInputDialog::getAtomStyle(atomStyle t)
{
  switch (t) {
    case angle:
      return "angle";
    case atomic:
      return "atomic";
    case bond:
      return "bond";
    case charge:
      return "charge";
    case dipole:
      return "dipole";
    case a_electron:
      return "electron";
    case ellipsoid:
      return "ellipsoid";
    case full:
      return "full";
    case line:
      return "line";
    case meso:
      return "meso";
    case molecular:
      return "molecular";
    case peri:
      return "peri";
    case sphere:
      return "sphere";
    case tri:
      return "tri";
    case wavepacket:
      return "wavepacket";
    default:
      return "full";
  }
}

QString LammpsInputDialog::getDimensionType(dimensionType t)
{
  switch (t) {
    case d2:
      return "2d";
    case d3:
      return "3d";
    default:
      return "3d";
  }
}

QString LammpsInputDialog::getXBoundaryType(boundaryType t)
{
  switch (t) {
    case p:
      return "p";
    case f:
      return "f";
    case s:
      return "s";
    case m:
      return "m";
    case fs:
      return "fs";
    case fm:
      return "fm";
    default:
      return "p";
  }
}

QString LammpsInputDialog::getYBoundaryType(boundaryType t)
{
  switch (t) {
    case p:
      return "p";
    case f:
      return "f";
    case s:
      return "s";
    case m:
      return "m";
    case fs:
      return "fs";
    case fm:
      return "fm";
    default:
      return "p";
  }
}

QString LammpsInputDialog::getZBoundaryType(boundaryType t)
{
  switch (t) {
    case p:
      return "p";
    case f:
      return "f";
    case s:
      return "s";
    case m:
      return "m";
    case fs:
      return "fs";
    case fm:
      return "fm";
    default:
      return "p";
  }
}

QString LammpsInputDialog::getWaterPotential(waterPotential t)
{
  switch (t) {
    case NONE: {
      QString waterPotentialInput;
      QTextStream water(&waterPotentialInput);
      water << "";
      return waterPotentialInput;
    }
    case SPC: {
      QString waterPotentialInput;
      QTextStream water(&waterPotentialInput);
      int Hydrogen;
      int Oxygen;
      determineAtomTypesSPC(Hydrogen, Oxygen);
      water << "# The SPC water potential\n"
            << "pair_style      lj/cut/coul/cut 9.8 9.8\n"
            << "pair_coeff      " << Oxygen << " " << Oxygen
            << " 0.15535 3.5533\n"
            << "pair_coeff      "
            << "* " << Hydrogen << " 0.00000 0.0000\n"
            << "bond_style      harmonic\n"
            << "angle_style     harmonic\n"
            << "dihedral_style  none\n"
            << "improper_style  none\n"
            << "bond_coeff      1 100.00   1.000\n"
            << "angle_coeff     1 100.00 109.47\n"
            << "special_bonds   lj/coul 0.0 0.0 0.5\n"
            << "fix             RigidOHBonds all shake 0.0001 20 0 b 1 a 1\n";
      return waterPotentialInput;
    }
    case SPCE: {
      QString waterPotentialInput;
      QTextStream water(&waterPotentialInput);
      int Hydrogen;
      int Oxygen;
      determineAtomTypesSPC(Hydrogen, Oxygen);
      water << "# The SPC/E water potential\n"
            << "pair_style      lj/cut/coul/long 9.8 9.8\n"
            << "kspace_style    pppm 1.0e-4\n"
            << "pair_coeff      " << Oxygen << " " << Oxygen
            << " 0.15535 3.5533\n"
            << "pair_coeff      "
            << "* " << Hydrogen << " 0.00000 0.0000\n"
            << "bond_style      harmonic\n"
            << "angle_style     harmonic\n"
            << "dihedral_style  none\n"
            << "improper_style  none\n"
            << "bond_coeff      1 100.00   1.000\n"
            << "angle_coeff     1 100.00 109.47\n"
            << "special_bonds   lj/coul 0.0 0.0 0.5\n"
            << "fix             RigidOHBonds all shake 0.0001 20 0 b 1 a 1\n";
      return waterPotentialInput;
    }
    default: {
      QString waterPotentialInput;
      QTextStream water(&waterPotentialInput);
      water << "\n";
      return waterPotentialInput;
    }
  }
}

QString LammpsInputDialog::getEnsemble(ensemble t)
{
  switch (t) {
    case NVT: {
      QString ensembleInput;
      QTextStream fix(&ensembleInput);
      fix << "fix            ensemble all nvt"
          << " temp " << fixed << qSetRealNumberPrecision(2) << m_temperature
          << " " << fixed << qSetRealNumberPrecision(2) << m_temperature
          << " 100 "
          << "tchain " << m_nhChain << "\n";
      return ensembleInput;
    }
    case NVE: {
      QString ensembleInput;
      QTextStream fix(&ensembleInput);
      fix << "fix            ensemble all nve\n";
      return ensembleInput;
    }
    default: {
      QString ensembleInput;
      QTextStream fix(&ensembleInput);
      fix << "fix            ensemble all nvt"
          << " temp " << fixed << qSetRealNumberPrecision(2) << m_temperature
          << " " << fixed << qSetRealNumberPrecision(2) << m_temperature
          << " 100 "
          << "tchain " << m_nhChain << "\n";
      return ensembleInput;
    }
  }
}

QString LammpsInputDialog::getVelocityDist(velocityDist t)
{
  switch (t) {
    case gaussian:
      return "gaussian";
    case uniform:
      return "uniform";
    default:
      return "gaussian";
  }
}

QString LammpsInputDialog::getZeroMOM()
{
  if (m_zeroMOM)
    return "yes";
  else
    return "no";
}

QString LammpsInputDialog::getZeroL()
{
  if (m_zeroL)
    return "yes";
  else
    return "no";
}

QString LammpsInputDialog::getThermoStyle(thermoStyle t)
{
  switch (t) {
    case one:
      return "one";
    case multi:
      return "multi";
    default:
      return "one";
  }
}

void LammpsInputDialog::deckDirty(bool dirty)
{
  m_dirty = dirty;
  ui.titleLine->setEnabled(!dirty);
  // ui.calculationCombo->setEnabled(!dirty);
  // ui.theoryCombo->setEnabled(!dirty);
  // ui.basisCombo->setEnabled(!dirty);
  // ui.multiplicitySpin->setEnabled(!dirty);
  // ui.chargeSpin->setEnabled(!dirty);
  ui.enableFormButton->setEnabled(dirty);
}

void LammpsInputDialog::readSettings(QSettings& settings)
{
  m_savePath = settings.value("lammps/savepath").toString();
}

void LammpsInputDialog::writeSettings(QSettings& settings) const
{
  settings.setValue("lammps/savepath", m_savePath);
}

void LammpsInputDialog::determineAtomTypesSPC(int& hyd, int& oxy)
{
  double ThisMass;
  QString ThisAtom;

  // QList<Core::Atom *> atoms = m_molecule->atoms();
  for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
    Core::Atom atom = m_molecule->atom(i);
    ThisMass = Core::Elements::mass(atom.atomicNumber());
    ThisAtom = Core::Elements::symbol(atom.atomicNumber());
    AtomMass[ThisAtom] = ThisMass;
  }
  int AtomIndex = 0;
  // Set AtomType integer
  for (itr = AtomMass.begin(); itr != AtomMass.end(); ++itr) {
    AtomIndex++;
    AtomType[itr.key()] = AtomIndex;
  }
  // this is on purpose due to the use of
  // unordered_map in OpenBabel, which
  // returns a different order for O and H.
  hyd = AtomType.value("O");
  oxy = AtomType.value("H");
}
}
}
