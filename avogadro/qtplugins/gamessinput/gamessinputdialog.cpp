/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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

using Avogadro::MoleQueue::JobObject;
using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;

namespace Avogadro::QtPlugins {

enum CalculateOption
{
  CalculateSinglePoint = 0,
  CalculateEquilibriumGeometry,
  CalculateTransitionState,
  CalculateForces,
  CalculateFrequencies,
  CalculateMakeEFP,

  CalculateCount
};

enum TheoryOption
{
  TheoryAM1 = 0,
  TheoryPM3,
  TheoryRHF,
  TheoryB3LYP,
  TheoryPBE0,
  TheorywB97X,
  TheorywB97XD,
  TheoryMP2,
  TheoryCCSDT,
  TheoryCRCCL,
  TheoryEOMCCSD,

  TheoryCount
};

enum BasisOption
{
  BasisSTO3G = 0,
  BasisSTO4G,
  BasisSTO5G,
  BasisSTO6G,
  BasisMINI,
  Basis321G,
  Basis631Gd,
  Basis631Gdp,
  Basis631PlusGdp,
  Basis631PlusG2dp,
  Basis6311PlusPlusG2dp,
  BasisMakeEFP,
  BasisCCD,
  BasisCCT,
  BasisCCQ,
  BasisCC5,
  BasisCC6,
  BasisAUGCCD,
  BasisAUGCCT,
  BasisAUGCCQ,
  BasisAUGCC5,
  BasisAUGCC6,
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

enum DispersionCorrectionOption
{
  DispersionNone = 0,
  DispersionD1,
  DispersionD2,
  DispersionD3,
  DispersionD4,

  DispersionCount
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

GamessInputDialog::~GamessInputDialog() {}

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
  connect(ui.DCVerCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.DCVerCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.stateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.multiplicityCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.chargeCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.maxscfspinBox, SIGNAL(valueChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.convergeSpinBox, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
}

void GamessInputDialog::connectPreview() {}

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
  buildDispersionCorrectionOptions();
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
  m_optionCache.insert(ui.DCVerCombo, ui.DCVerCombo->currentIndex());
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
      case CalculateForces:
        text = tr("Forces");
        break;
      case CalculateTransitionState:
        text = tr("Transition State");
        break;
      case CalculateFrequencies:
        text = tr("Frequencies");
        break;
      case CalculateMakeEFP:
        text = tr("Make EFP");
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
      case TheoryPBE0:
        text = "PBE0";
        break;
      case TheorywB97X:
        text = "wB97X";
        break;
      case TheorywB97XD:
        text = "wB97X-D";
        break;
      case TheoryMP2:
        text = "MP2";
        break;
      case TheoryCCSDT:
        text = "CCSD(T)";
        break;
      case TheoryCRCCL:
        text = "CR-CCL";
        break;
      case TheoryEOMCCSD:
        text = "EOM-CCSD";
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
      case BasisSTO4G:
        text = "STO-4G";
        break;
      case BasisSTO5G:
        text = "STO-5G";
        break;
      case BasisSTO6G:
        text = "STO-6G";
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
      case BasisMakeEFP:
        text = "6-311++G(3df,2p)";
        break;
      case BasisCCD:
        text = "cc-pVDZ";
        break;
      case BasisCCT:
        text = "cc-pVTZ";
        break;
      case BasisCCQ:
        text = "cc-pVQZ";
        break;
      case BasisCC5:
        text = "cc-pV5Z";
        break;
      case BasisCC6:
        text = "cc-pV6Z";
        break;
      case BasisAUGCCD:
        text = "aug-cc-pVDZ";
        break;
      case BasisAUGCCT:
        text = "aug-cc-pVTZ";
        break;
      case BasisAUGCCQ:
        text = "aug-cc-pVQZ";
        break;
      case BasisAUGCC5:
        text = "aug-cc-pV5Z";
        break;
      case BasisAUGCC6:
        text = "aug-cc-pV6Z";
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

void GamessInputDialog::buildDispersionCorrectionOptions()
{
  for (int i = 0; i < static_cast<int>(DispersionCount); ++i) {
    QString text = "";
    switch (static_cast<DispersionCorrectionOption>(i)) {
      case DispersionNone:
        text = tr("None");
        break;
      case DispersionD1:
        text = tr("D1");
        break;
      case DispersionD2:
        text = tr("D2");
        break;
      case DispersionD3:
        text = tr("D3");
        break;
      case DispersionD4:
        text = tr("D4");
        break;
      default:
        break;
    }
    ui.DCVerCombo->addItem(text);
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
  ui.theoryCombo->setCurrentIndex(TheorywB97X);
  ui.basisCombo->setCurrentIndex(Basis631Gd);
  ui.DCVerCombo->setCurrentIndex(DispersionD4);
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
  theory.replace(QRegularExpression("\\s+"), "");

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

  auto calculate(
    static_cast<CalculateOption>(ui.calculateCombo->currentIndex()));
  auto theory(static_cast<TheoryOption>(ui.theoryCombo->currentIndex()));
  auto basis(static_cast<BasisOption>(ui.basisCombo->currentIndex()));
  auto dispersion(
    static_cast<DispersionCorrectionOption>(ui.DCVerCombo->currentIndex()));
  auto state(static_cast<StateOption>(ui.stateCombo->currentIndex()));
  auto multiplicity(
    static_cast<MultiplicityOption>(ui.multiplicityCombo->currentIndex()));
  auto charge(static_cast<ChargeOption>(ui.chargeCombo->currentIndex()));

  // Disable basis selection for semiempirical methods.
  ui.basisCombo->setEnabled(theory != TheoryAM1 && theory != TheoryPM3);
  bool is_dft = (theory == TheoryB3LYP || theory == TheoryPBE0 ||
                 theory == TheorywB97X || theory == TheorywB97XD);
  ui.DCVerCombo->setEnabled(is_dft);

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
  QString extraDFT;

  // Optional lines
  QString statPt;
  QString force;
  QString pcm;
  QString maxSCF = QString::number(ui.maxscfspinBox->value());
  QString convthresh = QString::number(ui.convergeSpinBox->value());

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
    case CalculateForces:
      runTyp = "FORCE";
      force = " $FORCE METHOD=ANALYTIC $END\n";
      break;
    case CalculateFrequencies:
      runTyp = "HESSIAN";
      force = " $FORCE METHOD=ANALYTIC VIBANL=.TRUE. $END\n";
      break;
    case CalculateMakeEFP:
      runTyp = "MAKEFP";
      basis = BasisMakeEFP;
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
      extraDFT += " DFTTYP=B3LYP";
      break;
    case TheoryPBE0:
      extraDFT += " DFTTYP=PBE0";
      break;
    case TheorywB97X:
      extraDFT += " DFTTYP=wB97X";
      break;
    case TheorywB97XD:
      extraDFT += " DFTTYP=wB97X-D";
      break;
    case TheoryMP2:
      extraContrl += " MPLEVL=2";
      break;
    case TheoryCCSDT:
      extraContrl += " CCTYP=CCSD(T)";
      break;
    case TheoryCRCCL:
      extraContrl += " CCTYP=CR-CCL";
      break;
    case TheoryEOMCCSD:
      extraContrl += " CCTYP=EOM-CCSD";
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
      case BasisSTO4G:
        gBasis = "STO";
        extraBasis += " NGAUSS=4";
        break;
      case BasisSTO5G:
        gBasis = "STO";
        extraBasis += " NGAUSS=5";
        break;
      case BasisSTO6G:
        gBasis = "STO";
        extraBasis += " NGAUSS=6";
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
      case BasisMakeEFP:
        gBasis = "N311";
        extraBasis +=
          " NGAUSS=6 NDFUNC=3 NPFUNC=2 NFFUNC=3 \n DIFFSP=.TRUE. DIFFS=.TRUE.";
        break;
      case BasisCCD:
        gBasis = "ccd";
        break;
      case BasisCCT:
        gBasis = "cct";
        break;
      case BasisCCQ:
        gBasis = "ccq";
        break;
      case BasisCC5:
        gBasis = "cc5";
        break;
      case BasisCC6:
        gBasis = "cc6";
        break;
      case BasisAUGCCD:
        gBasis = "accd";
        break;
      case BasisAUGCCT:
        gBasis = "acct";
        break;
      case BasisAUGCCQ:
        gBasis = "accq";
        break;
      case BasisAUGCC5:
        gBasis = "acc5";
        break;
      case BasisAUGCC6:
        gBasis = "acc6";
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

  if (is_dft) {
    switch (dispersion) {
      case DispersionNone:
        extraDFT += " DC=.F. ";
        break;
      case DispersionD1:
        extraDFT += " DC=.T. IDCVER=1";
        break;
      case DispersionD2:
        extraDFT += " DC=.T. IDCVER=2";
        break;
      case DispersionD3:
        extraDFT += " DC=.T. IDCVER=3";
        break;
      case DispersionD4:
        extraDFT += " DC=.T. IDCVER=4";
        break;
      default:
        break;
    }
  }

  // build up the input file:
  QString file;
  file += "! Input file generated by Avogadro\n";
  file += QString(" $BASIS GBASIS=%1%2 $END\n").arg(gBasis, extraBasis);
  file += pcm;
  file += QString(" $CONTRL SCFTYP=%1 RUNTYP=%2 ICHARG=%3 MULT=%4%5 $END\n")
            .arg(scfTyp, runTyp, iCharg, mult, extraContrl);
  file += QString(" $CONTRL ISPHER=1 MAXIT=%1 $END\n").arg(maxSCF);
  file += QString(" $SCF DIRSCF=.T. CONV=%1 $END\n").arg(convthresh);
  if (is_dft) {
    file += QString(" $DFT %1 $END\n").arg(extraDFT);
  }
  file += statPt;
  file += force;
  file += "\n";
  file += " $DATA\n";
  file += QString("%1\n").arg(title);
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

} // namespace Avogadro::QtPlugins
