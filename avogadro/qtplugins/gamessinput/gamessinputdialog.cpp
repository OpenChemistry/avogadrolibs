/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gamessinputdialog.h"
#include "gamesshighlighter.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>

#include <avogadro/molequeue/molequeuedialog.h>
#include <avogadro/molequeue/molequeuemanager.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/molequeue/client/jobobject.h>
#include <qjsonarray.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

#include <QtWidgets/QFileDialog>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QProgressDialog>

#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QTimer>

using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;
using Avogadro::MoleQueue::JobObject;

namespace Avogadro {
namespace QtPlugins {

enum CalculateOption
{
  CalculateSinglePoint = 0,
  CalculateEquilibriumGeometry,
  CalculateTransitionState,
  CalculateFrequencies,

  CalculateCount
};

enum TheoryOption
{
  TheoryAM1 = 0,
  TheoryPM3,
  TheoryRHF,
  TheoryB3LYP,
  TheoryMP2,
  TheoryCCSDT,

  TheoryCount
};

enum BasisOption
{
  BasisSTO3G = 0,
  BasisMINI,
  Basis321G,
  Basis631Gd,
  Basis631Gdp,
  Basis631PlusGdp,
  Basis631PlusG2dp,
  Basis6311PlusPlusG2dp,
  BasisCorePotential,

  BasisCount
};

enum StateOption
{
  StateGas = 0,
  StateWater,

  StateCount
};

enum MultiplicityOption
{
  MultiplicitySinglet = 0,
  MultiplicityDoublet,
  MultiplicityTriplet,

  MultiplicityCount
};

enum ChargeOption
{
  ChargeDication = 0,
  ChargeCation,
  ChargeNeutral,
  ChargeAnion,
  ChargeDianion,

  ChargeCount
};

GamessInputDialog::GamessInputDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_molecule(nullptr), m_highlighter(nullptr),
    m_updatePending(false)
{
  ui.setupUi(this);
  m_highlighter = new GamessHighlighter(ui.previewText->document());

  buildOptions();

  connectBasic();
  connectPreview();
  connectButtons();

  setBasicDefaults();

  updatePreviewText();
}

GamessInputDialog::~GamessInputDialog()
{
}

void GamessInputDialog::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewText()));
  connect(mol, SIGNAL(changed(unsigned int)), SLOT(updateTitlePlaceholder()));

  updateTitlePlaceholder();
  updatePreviewText();
}

void GamessInputDialog::showEvent(QShowEvent* e)
{
  QWidget::showEvent(e);

  // Update the preview text if an update was requested while hidden. Use a
  // single shot to allow the dialog to show before popping up any warnings.
  if (m_updatePending)
    QTimer::singleShot(0, this, SLOT(updatePreviewText()));
}

void GamessInputDialog::connectBasic()
{
  connect(ui.titleEdit, SIGNAL(textChanged(QString)), this,
          SLOT(updatePreviewText()));
  connect(ui.calculateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.calculateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.basisCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.basisCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.stateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.multiplicityCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.chargeCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
}

void GamessInputDialog::connectPreview()
{
}

void GamessInputDialog::connectButtons()
{
  connect(ui.resetAllButton, SIGNAL(clicked()), SLOT(resetClicked()));
  connect(ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect(ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect(ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect(ui.closeButton, SIGNAL(clicked()), SLOT(close()));
}

void GamessInputDialog::buildOptions()
{
  buildCalculateOptions();
  buildTheoryOptions();
  buildBasisOptions();
  buildStateOptions();
  buildMultiplicityOptions();
  buildChargeOptions();
}

void GamessInputDialog::updateOptionCache()
{
  m_optionCache.clear();
  m_optionCache.insert(ui.calculateCombo, ui.calculateCombo->currentIndex());
  m_optionCache.insert(ui.theoryCombo, ui.theoryCombo->currentIndex());
  m_optionCache.insert(ui.basisCombo, ui.basisCombo->currentIndex());
  m_optionCache.insert(ui.stateCombo, ui.stateCombo->currentIndex());
  m_optionCache.insert(ui.multiplicityCombo,
                       ui.multiplicityCombo->currentIndex());
  m_optionCache.insert(ui.chargeCombo, ui.chargeCombo->currentIndex());
}

void GamessInputDialog::restoreOptionCache()
{
  foreach (QComboBox* combo, m_optionCache.keys()) {
    combo->blockSignals(true);
    combo->setCurrentIndex(m_optionCache.value(combo, 0));
    combo->blockSignals(false);
  }
}

void GamessInputDialog::buildCalculateOptions()
{
  for (int i = 0; i < static_cast<int>(CalculateCount); ++i) {
    QString text = "";
    switch (static_cast<CalculateOption>(i)) {
      case CalculateSinglePoint:
        text = tr("Single Point");
        break;
      case CalculateEquilibriumGeometry:
        text = tr("Equilibrium Geometry");
        break;
      case CalculateTransitionState:
        text = tr("Transition State");
        break;
      case CalculateFrequencies:
        text = tr("Frequencies");
        break;
      default:
        break;
    }
    ui.calculateCombo->addItem(text);
  }
}

void GamessInputDialog::buildTheoryOptions()
{
  for (int i = 0; i < static_cast<int>(TheoryCount); ++i) {
    QString text = "";
    switch (static_cast<TheoryOption>(i)) {
      case TheoryAM1:
        text = "AM1";
        break;
      case TheoryPM3:
        text = "PM3";
        break;
      case TheoryRHF:
        text = "RHF";
        break;
      case TheoryB3LYP:
        text = "B3LYP";
        break;
      case TheoryMP2:
        text = "MP2";
        break;
      case TheoryCCSDT:
        text = "CCSD(T)";
        break;
      default:
        break;
    }
    ui.theoryCombo->addItem(text);
  }
}

void GamessInputDialog::buildBasisOptions()
{
  for (int i = 0; i < static_cast<int>(BasisCount); ++i) {
    QString text = "";
    switch (static_cast<BasisOption>(i)) {
      case BasisSTO3G:
        text = "STO-3G";
        break;
      case BasisMINI:
        text = "MINI";
        break;
      case Basis321G:
        text = "3-21 G";
        break;
      case Basis631Gd:
        text = "6-31 G(d)";
        break;
      case Basis631Gdp:
        text = "6-31 G(d,p)";
        break;
      case Basis631PlusGdp:
        text = "6-31+G(d,p)";
        break;
      case Basis631PlusG2dp:
        text = "6-31+G(2d,p)";
        break;
      case Basis6311PlusPlusG2dp:
        text = "6-311++G(2d,p)";
        break;
      case BasisCorePotential:
        text = tr("Core Potential");
        break;
      default:
        break;
    }
    ui.basisCombo->addItem(text);
  }
}

void GamessInputDialog::buildStateOptions()
{
  for (int i = 0; i < static_cast<int>(StateCount); ++i) {
    QString text = "";
    switch (static_cast<StateOption>(i)) {
      case StateGas:
        text = tr("Gas");
        break;
      case StateWater:
        text = tr("Water");
        break;
      default:
        break;
    }
    ui.stateCombo->addItem(text);
  }
}

void GamessInputDialog::buildMultiplicityOptions()
{
  for (int i = 0; i < static_cast<int>(MultiplicityCount); ++i) {
    QString text = "";
    switch (static_cast<MultiplicityOption>(i)) {
      case MultiplicitySinglet:
        text = tr("Singlet");
        break;
      case MultiplicityDoublet:
        text = tr("Doublet");
        break;
      case MultiplicityTriplet:
        text = tr("Triplet");
        break;
      default:
        break;
    }
    ui.multiplicityCombo->addItem(text);
  }
}

void GamessInputDialog::buildChargeOptions()
{
  for (int i = 0; i < static_cast<int>(ChargeCount); ++i) {
    QString text = "";
    switch (static_cast<ChargeOption>(i)) {
      case ChargeDication:
        text = tr("Dication");
        break;
      case ChargeCation:
        text = tr("Cation");
        break;
      case ChargeNeutral:
        text = tr("Neutral");
        break;
      case ChargeAnion:
        text = tr("Anion");
        break;
      case ChargeDianion:
        text = tr("Dianion");
        break;
      default:
        break;
    }
    ui.chargeCombo->addItem(text);
  }
}

void GamessInputDialog::setBasicDefaults()
{
  ui.titleEdit->setText(QString());
  ui.calculateCombo->setCurrentIndex(CalculateSinglePoint);
  ui.theoryCombo->setCurrentIndex(TheoryB3LYP);
  ui.basisCombo->setCurrentIndex(Basis321G);
  ui.stateCombo->setCurrentIndex(StateGas);
  ui.multiplicityCombo->setCurrentIndex(MultiplicitySinglet);
  ui.chargeCombo->setCurrentIndex(ChargeNeutral);
}

QString GamessInputDialog::generateJobTitle() const
{
  QString calculation(ui.calculateCombo->currentText());
  QString theory(ui.theoryCombo->currentText());
  QString basis(ui.basisCombo->currentText());
  QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                             : tr("[no molecule]"));

  // Merge theory/basis into theory
  theory += "/" + basis;
  theory.replace(QRegExp("\\s+"), "");

  return QString("%1 | %2 | %3").arg(formula, calculation, theory);
}

void GamessInputDialog::updatePreviewText()
{
  // If the dialog is not shown, delay the update in case we need to prompt the
  // user to overwrite changes. Set the m_updatePending flag to true so we'll
  // know to update in the show event.
  if (!isVisible()) {
    m_updatePending = true;
    return;
  }

  m_updatePending = false;

  // Has the preview text been modified?
  if (ui.previewText->document()->isModified()) {
    QString message = tr("The input file has been modified. "
                         "Would you like to overwrite your changes to reflect "
                         "the new geometry or job options?");
    int response = QMessageBox::question(
      this, tr("Overwrite modified input file?"), message,
      QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (static_cast<QMessageBox::StandardButton>(response) !=
        QMessageBox::Yes) {
      restoreOptionCache();
      return;
    }
  }

  // Gather options:
  QString title(ui.titleEdit->text());
  if (title.isEmpty())
    title = generateJobTitle();

  CalculateOption calculate(
    static_cast<CalculateOption>(ui.calculateCombo->currentIndex()));
  TheoryOption theory(
    static_cast<TheoryOption>(ui.theoryCombo->currentIndex()));
  BasisOption basis(static_cast<BasisOption>(ui.basisCombo->currentIndex()));
  StateOption state(static_cast<StateOption>(ui.stateCombo->currentIndex()));
  MultiplicityOption multiplicity(
    static_cast<MultiplicityOption>(ui.multiplicityCombo->currentIndex()));
  ChargeOption charge(
    static_cast<ChargeOption>(ui.chargeCombo->currentIndex()));

  // Disable basis selection for semiempirical methods.
  ui.basisCombo->setEnabled(theory != TheoryAM1 && theory != TheoryPM3);

  // Generate text.
  //   Variables:
  QString runTyp;
  QString scfTyp;
  QString gBasis;
  QString mult;
  QString iCharg;

  // Extra options for lines
  QString extraBasis;
  QString extraContrl;

  // Optional lines
  QString statPt;
  QString force;
  QString pcm;

  switch (calculate) {
    case CalculateSinglePoint:
      runTyp = "ENERGY";
      break;
    case CalculateEquilibriumGeometry:
      runTyp = "OPTIMIZE";
      statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n";
      break;
    case CalculateTransitionState:
      runTyp = "SADPOINT";
      statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n";
      break;
    case CalculateFrequencies:
      runTyp = "HESSIAN";
      force = " $FORCE METHOD=ANALYTIC VIBANL=.TRUE. $END\n";
      break;
    default:
      break;
  }

  switch (theory) {
    case TheoryAM1:
      gBasis = "AM1";
      break;
    case TheoryPM3:
      gBasis = "PM3";
      break;
    case TheoryRHF:
      break;
    case TheoryB3LYP:
      extraContrl += " DFTTYP=B3LYP";
      break;
    case TheoryMP2:
      extraContrl += " MPLEVL=2";
      break;
    case TheoryCCSDT:
      extraContrl += " CCTYP=CCSD(T)";
      break;
    default:
      break;
  }

  if (theory != TheoryAM1 && theory != TheoryPM3) {
    switch (basis) {
      case BasisSTO3G:
        gBasis = "STO";
        extraBasis += " NGAUSS=3";
        break;
      case BasisMINI:
        gBasis = "MINI";
        break;
      case Basis321G:
        gBasis = "N21";
        extraBasis += " NGAUSS=3";
        break;
      case Basis631Gd:
        gBasis = "N31";
        extraBasis += " NGAUSS=6 NDFUNC=1";
        break;
      case Basis631Gdp:
        gBasis = "N31";
        extraBasis += " NGAUSS=6 NDFUNC=1 NPFUNC=1";
        break;
      case Basis631PlusGdp:
        gBasis = "N31";
        extraBasis += " NGAUSS=6 NDFUNC=1 NPFUNC=1 DIFFSP=.TRUE.";
        break;
      case Basis631PlusG2dp:
        gBasis = "N31";
        extraBasis += " NGAUSS=6 NDFUNC=2 NPFUNC=1 DIFFSP=.TRUE.";
        break;
      case Basis6311PlusPlusG2dp:
        gBasis = "N311";
        extraBasis += " NGAUSS=6 NDFUNC=2 NPFUNC=1 DIFFSP=.TRUE. DIFFS=.TRUE.";
        break;
      case BasisCorePotential:
        gBasis = "SBK";
        extraBasis += " NGAUSS=3 NDFUNC=1";
        extraContrl += " ECP=SBK";
        break;
      default:
        break;
    }
  }

  switch (state) {
    case StateGas:
      break;
    case StateWater:
      pcm = " $PCM SOLVNT=WATER $END\n";
      break;
    default:
      break;
  }

  switch (multiplicity) {
    case MultiplicitySinglet:
      scfTyp = "RHF";
      mult = "1";
      break;
    case MultiplicityDoublet:
      scfTyp = "ROHF";
      mult = "2";
      break;
    case MultiplicityTriplet:
      scfTyp = "ROHF";
      mult = "3";
      break;
    default:
      break;
  }

  switch (charge) {
    case ChargeDication:
      iCharg = "2";
      break;
    case ChargeCation:
      iCharg = "1";
      break;
    case ChargeNeutral:
      iCharg = "0";
      break;
    case ChargeAnion:
      iCharg = "-1";
      break;
    case ChargeDianion:
      iCharg = "-2";
      break;
    default:
      break;
  }

  // build up the input file:
  QString file;
  file += QString("! %1\n").arg(title);
  file += QString(" $BASIS GBASIS=%1%2 $END\n").arg(gBasis, extraBasis);
  file += pcm;
  file += QString(" $CONTRL SCFTYP=%1 RUNTYP=%2 ICHARG=%3 MULT=%4%5 $END\n")
            .arg(scfTyp, runTyp, iCharg, mult, extraContrl);
  file += statPt;
  file += force;
  file += "\n";
  file += " $DATA\n";
  file += "Title\n";
  file += "C1\n";

  if (m_molecule) {
    for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
      Core::Atom atom = m_molecule->atom(i);
      file += QString("%1 %2 %3 %4 %5\n")
                .arg(Core::Elements::symbol(atom.atomicNumber()), -3)
                .arg(static_cast<float>(atom.atomicNumber()), 5, 'f', 1)
                .arg(atom.position3d().x(), 9, 'f', 5)
                .arg(atom.position3d().y(), 9, 'f', 5)
                .arg(atom.position3d().z(), 9, 'f', 5);
    }
  }

  file += " $END\n";

  ui.previewText->setText(file);
  ui.previewText->document()->setModified(false);
  updateOptionCache();
}

void GamessInputDialog::resetClicked()
{
  setBasicDefaults();
  updatePreviewText();
}

void GamessInputDialog::defaultsClicked()
{
  setBasicDefaults();
  updatePreviewText();
}

void GamessInputDialog::generateClicked()
{
  QSettings settings;
  QString fileName =
    (ui.baseNameEdit->text().isEmpty() ? ui.baseNameEdit->placeholderText()
                                       : ui.baseNameEdit->text()) +
    ".inp";
  QString targetFile =
    settings.value("gamessInput/outputDirectory", QDir::homePath()).toString();
  targetFile =
    QDir(QFileInfo(targetFile).absoluteDir()).absoluteFilePath(fileName);

  fileName = QFileDialog::getSaveFileName(this, tr("Save GAMESS input file"),
                                          targetFile);

  // User cancel:
  if (fileName.isNull())
    return;

  settings.setValue("gamessInput/outputDirectory", fileName);

  QFile file(fileName);
  bool success = false;
  if (file.open(QFile::WriteOnly | QFile::Text)) {
    if (file.write(ui.previewText->toPlainText().toLocal8Bit()) > 0) {
      success = true;
    }
    file.close();
  }

  if (!success) {
    QMessageBox::critical(this, tr("Output Error"),
                          tr("Failed to write to file %1.").arg(fileName));
  }
}

void GamessInputDialog::computeClicked()
{
  // Verify that molequeue is running:
  MoleQueueManager& mqManager = MoleQueueManager::instance();
  if (!mqManager.connectIfNeeded()) {
    QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                             tr("Cannot connect to MoleQueue server. Please "
                                "ensure that it is running and try again."));
    return;
  }

  QString description(ui.titleEdit->text());
  if (description.isEmpty())
    description = generateJobTitle();

  QString fileNameBase = ui.baseNameEdit->text().isEmpty()
                           ? ui.baseNameEdit->placeholderText()
                           : ui.baseNameEdit->text();

  JobObject job;
  job.setProgram("GAMESS");
  job.setDescription(description);
  job.setInputFile(QString("%1.inp").arg(fileNameBase),
                   ui.previewText->toPlainText());

  MoleQueueDialog::SubmitStatus submitStatus =
    MoleQueueDialog::submitJob(this, tr("Submit GAMESS Calculation"), job,
                               MoleQueueDialog::WaitForSubmissionResponse |
                                 MoleQueueDialog::SelectProgramFromTemplate);

  switch (submitStatus) {
    default:
    case MoleQueueDialog::SubmissionSuccessful:
    case MoleQueueDialog::SubmissionFailed:
    case MoleQueueDialog::SubmissionAttempted:
    case MoleQueueDialog::SubmissionAborted:
      // The dialog handles these cases adequately, we don't need to do
      // anything.
      break;

    case MoleQueueDialog::JobFailed:
      // Inform the user:
      QMessageBox::information(this, tr("Job Failed"),
                               tr("The job did not complete successfully."),
                               QMessageBox::Ok);
      break;

    case MoleQueueDialog::JobFinished:
      // Let the world know that the job is ready to open. job has been
      // overwritten with the final job details.
      emit openJobOutput(job);
      hide();
      break;
  }
}

void GamessInputDialog::updateTitlePlaceholder()
{
  ui.titleEdit->setPlaceholderText(generateJobTitle());
}

} // end namespace QtPlugins
} // end namespace Avogadro
