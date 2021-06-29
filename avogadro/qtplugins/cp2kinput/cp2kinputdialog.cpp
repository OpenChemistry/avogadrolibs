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

#include "cp2kinputdialog.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/unitcell.h>

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

#include <map>
#include <vector>

using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;
using Avogadro::MoleQueue::JobObject;

namespace Avogadro {
namespace QtPlugins {

enum CalculateOption
{
  CalculateEnergy = 0,
  CalculateEnergyAndForces,
  CalculateMolecularDynamics,
  CalculateGeometryOptimization,

  CalculateCount
};

enum FunctionalOption
{
  FunctionalBLYP = 0,
  FunctionalBP,
  FunctionalHCTH120,
  FunctionalPADE,
  FunctionalPBE,

  FunctionalCount
};

enum BasisOption
{
  BasisSZVGTH = 0,
  BasisDZVGTH,
  BasisDZVPGTH,
  BasisTZVPGTH,
  BasisTZV2PGTH,

  BasisCount
};

enum MethodOption
{
  DFT = 0,
  MolecularMechanics,
  HybridQuantumClassical,

  MethodCount
};

// MM tab
enum EWALDTypeOption
{
  EWALD = 0,
  ewaldNONE,
  PME,
  SPME,

  EWALDTypeCount
};
// QM tab
enum SCFGuessOption
{
  ATOMIC = 0,
  CORE,
  DENSITIES,
  HISTORY_RESTART,
  MOPAC,
  scfNONE,
  RANDOM,
  RESTART,
  SPARSE,

  SCFGuessCount
};

enum OTMinimizerOption
{
  CG = 0,
  BROYDEN,
  DIIS,
  SD,

  OTMinimizerCount
};

Cp2kInputDialog::Cp2kInputDialog(QWidget* parent_, Qt::WindowFlags f)
  : QDialog(parent_, f), m_molecule(nullptr),
    // m_highlighter(NULL),
    m_updatePending(false)
{
  ui.setupUi(this);
  //  m_highlighter = new Cp2kHighlighter(ui.previewText->document());

  buildOptions();

  connectBasic();
  connectPreview();
  connectButtons();

  setBasicDefaults();

  updatePreviewText();
}

Cp2kInputDialog::~Cp2kInputDialog() {}

void Cp2kInputDialog::setMolecule(QtGui::Molecule* mol)
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

void Cp2kInputDialog::showEvent(QShowEvent* e)
{
  QWidget::showEvent(e);

  // Update the preview text if an update was requested while hidden. Use a
  // single shot to allow the dialog to show before popping up any warnings.
  if (m_updatePending)
    QTimer::singleShot(0, this, SLOT(updatePreviewText()));
}

void Cp2kInputDialog::connectBasic()
{
  connect(ui.titleEdit, SIGNAL(textChanged(QString)), this,
          SLOT(updatePreviewText()));
  connect(ui.calculateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.calculateCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.functionalCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.functionalCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.basisCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.basisCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updateTitlePlaceholder()));
  connect(ui.methodCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.ewaldtypeCombo, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.emaxSplineSpin, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.rcutnbSplineSpin, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.ewaldalphaSpin, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.ewaldgmaxSpin, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.lsdcheckBox, SIGNAL(stateChanged(bool)), this,
          SLOT(updatePreviewText()));
  connect(ui.maxscfspinBox, SIGNAL(valueChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.epsscfSpinBox, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.outerMaxscfSpinBox, SIGNAL(valueChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.outerEpsscfSpinBox, SIGNAL(valueChanged(double)), this,
          SLOT(updatePreviewText()));
  connect(ui.scfguessComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
  connect(ui.otminimizerComboBox, SIGNAL(currentIndexChanged(int)), this,
          SLOT(updatePreviewText()));
}

void Cp2kInputDialog::connectPreview() {}

void Cp2kInputDialog::connectButtons()
{
  connect(ui.resetAllButton, SIGNAL(clicked()), SLOT(resetClicked()));
  connect(ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect(ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect(ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect(ui.closeButton, SIGNAL(clicked()), SLOT(close()));
}

void Cp2kInputDialog::buildOptions()
{
  buildCalculateOptions();
  buildFunctionalOptions();
  buildBasisOptions();
  buildMethodOptions();
  buildEWALDTypeOptions();
  buildSCFGuessOptions();
  buildOTMinimizerOptions();
}

void Cp2kInputDialog::updateOptionCache()
{
  m_optionCache.clear();
  m_optionCache.insert(ui.calculateCombo, ui.calculateCombo->currentIndex());
  m_optionCache.insert(ui.functionalCombo, ui.functionalCombo->currentIndex());
  m_optionCache.insert(ui.basisCombo, ui.basisCombo->currentIndex());
  m_optionCache.insert(ui.methodCombo, ui.methodCombo->currentIndex());
  m_optionCache.insert(ui.ewaldtypeCombo, ui.ewaldtypeCombo->currentIndex());
  m_optionCache.insert(ui.scfguessComboBox,
                       ui.scfguessComboBox->currentIndex());
  m_optionCache.insert(ui.otminimizerComboBox,
                       ui.otminimizerComboBox->currentIndex());
}

void Cp2kInputDialog::restoreOptionCache()
{
  foreach (QComboBox* combo, m_optionCache.keys()) {
    combo->blockSignals(true);
    combo->setCurrentIndex(m_optionCache.value(combo, 0));
    combo->blockSignals(false);
  }
}

void Cp2kInputDialog::buildCalculateOptions()
{
  for (int i = 0; i < static_cast<int>(CalculateCount); ++i) {
    QString text = "";
    switch (static_cast<CalculateOption>(i)) {
      case CalculateEnergy:
        text = tr("Energy");
        break;
      case CalculateEnergyAndForces:
        text = tr("Energy and Forces");
        break;
      case CalculateMolecularDynamics:
        text = tr("Molecular Dynamics");
        break;
      case CalculateGeometryOptimization:
        text = tr("Geometry Optimization");
        break;
      default:
        break;
    }
    ui.calculateCombo->addItem(text);
  }
}

void Cp2kInputDialog::buildFunctionalOptions()
{
  for (int i = 0; i < static_cast<int>(FunctionalCount); ++i) {
    QString text = "";
    switch (static_cast<FunctionalOption>(i)) {
      case FunctionalBLYP:
        text = "BLYP";
        break;
      case FunctionalBP:
        text = "BP";
        break;
      case FunctionalHCTH120:
        text = "HCTH120";
        break;
      case FunctionalPADE:
        text = "PADE";
        break;
      case FunctionalPBE:
        text = "PBE";
        break;
      default:
        break;
    }
    ui.functionalCombo->addItem(text);
  }
}

void Cp2kInputDialog::buildBasisOptions()
{
  for (int i = 0; i < static_cast<int>(BasisCount); ++i) {
    QString text = "";
    switch (static_cast<BasisOption>(i)) {
      case BasisSZVGTH:
        text = "SZV-GTH";
        break;
      case BasisDZVGTH:
        text = "DZV-GTH";
        break;
      case BasisDZVPGTH:
        text = "DZVP-GTH";
        break;
      case BasisTZVPGTH:
        text = "TZVP-GTH";
        break;
      case BasisTZV2PGTH:
        text = "TZV2P-GTH";
        break;
      default:
        break;
    }
    ui.basisCombo->addItem(text);
  }
}

void Cp2kInputDialog::buildMethodOptions()
{
  for (int i = 0; i < static_cast<int>(MethodCount); ++i) {
    QString text = "";
    switch (static_cast<MethodOption>(i)) {
      case DFT:
        text = tr("Electronic structure methods (DFT)");
        break;
      case MolecularMechanics:
        text = tr("Molecular Mechanics");
        break;
      case HybridQuantumClassical:
        text = tr("Hybrid quantum classical (Not yet supported)");
        break;
      default:
        break;
    }
    ui.methodCombo->addItem(text);
  }
}

void Cp2kInputDialog::buildEWALDTypeOptions()
{
  for (int i = 0; i < static_cast<int>(EWALDTypeCount); ++i) {
    QString text = "";
    switch (static_cast<EWALDTypeOption>(i)) {
      case EWALD:
        text = tr("EWALD");
        break;
      case ewaldNONE:
        text = tr("NONE");
        break;
      case PME:
        text = tr("PME");
        break;
      case SPME:
        text = tr("SPME");
        break;
      default:
        break;
    }
    ui.ewaldtypeCombo->addItem(text);
  }
}
void Cp2kInputDialog::buildSCFGuessOptions()
{
  for (int i = 0; i < static_cast<int>(SCFGuessCount); ++i) {
    QString text = "";
    switch (static_cast<SCFGuessOption>(i)) {
      case ATOMIC:
        text = tr("ATOMIC");
        break;
      case CORE:
        text = tr("CORE");
        break;
      case DENSITIES:
        text = tr("DENSITIES");
        break;
      case HISTORY_RESTART:
        text = tr("HISTORY_RESTART");
        break;
      case MOPAC:
        text = tr("MOPAC");
        break;
      case scfNONE:
        text = tr("NONE");
        break;
      case RANDOM:
        text = tr("RANDOM");
        break;
      case RESTART:
        text = tr("RESTART");
        break;
      case SPARSE:
        text = tr("SPARSE");
        break;
      default:
        break;
    }
    ui.scfguessComboBox->addItem(text);
  }
}
void Cp2kInputDialog::buildOTMinimizerOptions()
{
  for (int i = 0; i < static_cast<int>(OTMinimizerCount); ++i) {
    QString text = "";
    switch (static_cast<OTMinimizerOption>(i)) {
      case BROYDEN:
        text = tr("BROYDEN");
        break;
      case CG:
        text = tr("Conjugate Gradients");
        break;
      case DIIS:
        text = tr("DIIS");
        break;
      case SD:
        text = tr("Steepest descent");
        break;
      default:
        break;
    }
    ui.otminimizerComboBox->addItem(text);
  }
}

void Cp2kInputDialog::setBasicDefaults()
{
  ui.titleEdit->setText(QString());
  ui.calculateCombo->setCurrentIndex(CalculateEnergy);
  ui.functionalCombo->setCurrentIndex(FunctionalBLYP);
  ui.basisCombo->setCurrentIndex(BasisSZVGTH);
  ui.methodCombo->setCurrentIndex(DFT);
  ui.ewaldtypeCombo->setCurrentIndex(SPME);
  ui.scfguessComboBox->setCurrentIndex(ATOMIC);
  ui.otminimizerComboBox->setCurrentIndex(CG);
}

QString Cp2kInputDialog::generateJobTitle() const
{
  QString calculation(ui.calculateCombo->currentText());
  QString basis(ui.basisCombo->currentText());
  QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                             : tr("[no molecule]"));

  // Merge theory/basis into theory
  //  replace(QRegExp("\\s+"), "");

  return QString("%1 | %2 | %3").arg(formula, calculation, basis);
}

void Cp2kInputDialog::updatePreviewText()
{
  std::map<QString, int> valencee;

  valencee["H"] = 1;
  valencee["He"] = 2;
  valencee["Li"] = 3;
  valencee["Be"] = 4;
  valencee["B"] = 3;
  valencee["C"] = 4;
  valencee["N"] = 5;
  valencee["O"] = 6;
  valencee["F"] = 7;
  valencee["Ne"] = 8;
  valencee["Na"] = 9;
  valencee["Mg"] = 10;
  valencee["Al"] = 3;
  valencee["Si"] = 4;
  valencee["P"] = 5;
  valencee["S"] = 6;
  valencee["Cl"] = 7;
  valencee["Ar"] = 8;
  valencee["K"] = 9;
  valencee["Ca"] = 10;
  valencee["Sc"] = 11;
  valencee["Ti"] = 12;
  valencee["V"] = 13;
  valencee["Cr"] = 14;
  valencee["Mn"] = 15;
  valencee["Fe"] = 16;
  valencee["Co"] = 17;
  valencee["Ni"] = 18;
  valencee["Cu"] = 11;
  valencee["Zn"] = 12;
  valencee["Ga"] = 13;
  valencee["Ge"] = 4;
  valencee["As"] = 5;
  valencee["Se"] = 6;
  valencee["Br"] = 7;
  valencee["Kr"] = 8;
  valencee["As"] = 5;
  valencee["Sr"] = 10;
  valencee["Y"] = 11;
  valencee["Zr"] = 12;
  valencee["Mo"] = 14;
  valencee["Ru"] = 16;
  valencee["Rh"] = 17;
  valencee["Pd"] = 18;
  valencee["Ag"] = 11;
  valencee["In"] = 13;
  valencee["Sb"] = 5;
  valencee["Te"] = 6;
  valencee["I"] = 7;
  valencee["Ba"] = 10;
  valencee["W"] = 14;
  valencee["Au"] = 11;
  valencee["Bi"] = 15;

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
  FunctionalOption functional(
    static_cast<FunctionalOption>(ui.functionalCombo->currentIndex()));
  BasisOption basis(static_cast<BasisOption>(ui.basisCombo->currentIndex()));
  MethodOption method(
    static_cast<MethodOption>(ui.methodCombo->currentIndex()));
  EWALDTypeOption EWALDType(
    static_cast<EWALDTypeOption>(ui.ewaldtypeCombo->currentIndex()));
  SCFGuessOption SCFGuess(
    static_cast<SCFGuessOption>(ui.scfguessComboBox->currentIndex()));
  OTMinimizerOption OTMinimizer(
    static_cast<OTMinimizerOption>(ui.otminimizerComboBox->currentIndex()));

  QString emaxSpline = QString::number(ui.emaxSplineSpin->value());
  QString rcutnb = QString::number(ui.rcutnbSplineSpin->value());
  QString ewaldalpha = QString::number(ui.ewaldalphaSpin->value());
  QString ewaldgmax = QString::number(ui.ewaldgmaxSpin->value());

  QString maxSCF = QString::number(ui.maxscfspinBox->value());
  QString epsSCF = QString::number(ui.epsscfSpinBox->value());
  QString outermaxSCF = QString::number(ui.outerMaxscfSpinBox->value());
  QString outerepsSCF = QString::number(ui.outerEpsscfSpinBox->value());

  // Generate text.
  //   Variables:
  QString runTyp;
  QString scfTyp;
  QString gbasis;
  QString gfunc;
  QString gmethod;
  QString mult;
  QString ewaldtype;
  QString lsd;

  QString scfGuess;
  QString otMinimizer;

  // Extra options for lines
  QString extraBasis;
  QString extraContrl;

  // Optional lines
  QString statPt;
  QString force;
  QString pcm;

  switch (calculate) {
    case CalculateEnergy:
      runTyp = "ENERGY";
      break;
    case CalculateEnergyAndForces:
      runTyp = "ENERGY_FORCE";
      break;
    case CalculateMolecularDynamics:
      runTyp = "MOLECULAR_DYNAMICS";
      break;
    case CalculateGeometryOptimization:
      runTyp = "GEO_OPT";
      break;
    default:
      break;
  }

  switch (functional) {
    case FunctionalBLYP:
      gfunc = "BLYP";
      break;
    case FunctionalBP:
      gfunc = "BP";
      break;
    case FunctionalHCTH120:
      gfunc = "HCTH120";
      break;
    case FunctionalPADE:
      gfunc = "PADE";
      break;
    case FunctionalPBE:
      gfunc = "PBE";
      break;
    default:
      break;
  }

  switch (basis) {
    case BasisSZVGTH:
      gbasis = "SZV-GTH";
      break;
    case BasisDZVGTH:
      gbasis = "DZV-GTH";
      break;
    case BasisDZVPGTH:
      gbasis = "DZVP-GTH";
      break;
    case BasisTZVPGTH:
      gbasis = "TZVP-GTH";
      break;
    case BasisTZV2PGTH:
      gbasis = "TZV2P-GTH";
      break;
    default:
      break;
  }

  switch (method) {
    case DFT:
      gmethod = "DFT";
      break;
    case MolecularMechanics:
      gmethod = "FIST";
      break;
    case HybridQuantumClassical:
      gmethod = "QMMM";
      break;
    default:
      break;
  }

  switch (EWALDType) {
    case EWALD:
      ewaldtype = "EWALD";
      break;
    case ewaldNONE:
      ewaldtype = "NONE";
      break;
    case PME:
      ewaldtype = "PME";
      break;
    case SPME:
      ewaldtype = "SPME";
      break;
    default:
      break;
  }

  switch (SCFGuess) {
    case ATOMIC:
      scfGuess = "ATOMIC";
      break;
    case CORE:
      scfGuess = "CORE";
      break;
    case DENSITIES:
      scfGuess = "DENSITIES";
      break;
    case HISTORY_RESTART:
      scfGuess = "HISTORY_RESTART";
      break;
    case MOPAC:
      scfGuess = "MOPAC";
      break;
    case scfNONE:
      scfGuess = "NONE";
      break;
    case RANDOM:
      scfGuess = "RANDOM";
      break;
    case RESTART:
      scfGuess = "RESTART";
      break;
    case SPARSE:
      scfGuess = "SPARSE";
      break;
    default:
      break;
  }

  switch (OTMinimizer) {
    case BROYDEN:
      otMinimizer = "BROYDEN";
      break;
    case CG:
      otMinimizer = "CG";
      break;
    case DIIS:
      otMinimizer = "DIIS";
      break;
    case SD:
      otMinimizer = "SD";
      break;
    default:
      break;
  }
  /*
  switch (lsdbool) {
  case true:
    lsd = "TRUE";
    break;
  case false:
        lsd = "FALSE";
    break;

  }*/

  // build up the input file:
  QString file;

  file += "&GLOBAL\n";
  file += QString("  PROJECT %1\n").arg(title);

  file += QString("  RUN_TYPE %1\n").arg(runTyp);

  file += "  PRINT_LEVEL LOW\n";
  file += "&END GLOBAL\n\n";

  file += "&FORCE_EVAL\n";

  file += QString("  METHOD %1\n").arg(gmethod);
  file += "&END FORCE_EVAL\n";

  if (m_molecule) {
    std::vector<int> atomList;
    bool inlist = true;

    for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
      Core::Atom atom = m_molecule->atom(i);
      for (int i = 0; i < atomList.size(); i++) {
        if (atomList.at(i) == atom.atomicNumber()) {
          inlist = false;
          break;
        } else {
          inlist = true;
        }
      }
      if (inlist) {
        atomList.push_back(atom.atomicNumber());
        QString symbol = Core::Elements::symbol(atom.atomicNumber());
        file += QString("    &KIND %1\n").arg(symbol);
        file += QString("        ELEMENT %1\n")
                  .arg(Core::Elements::symbol(atom.atomicNumber()));
        file += QString("        BASIS_SET %1\n").arg(gbasis);
        file += QString("        POTENTIAL GTH-%1-q%2\n")
                  .arg(gfunc)
                  .arg(valencee[symbol]);
      }
    }
  }

  // unit cell
  file += "    &CELL\n";
  if (const Core::UnitCell* cell = m_molecule->unitCell()) {
    Vector3f a = cell->aVector().cast<float>();
    Vector3f b = cell->bVector().cast<float>();
    Vector3f c = cell->cVector().cast<float>();

    file += QStringLiteral("    A%1%2%3\n")
              .arg(a.x(), 16, 'f', 7)
              .arg(a.y(), 16, 'f', 7)
              .arg(a.z(), 16, 'f', 7);
    file += QStringLiteral("    B%1%2%3\n")
              .arg(b.x(), 16, 'f', 7)
              .arg(b.y(), 16, 'f', 7)
              .arg(b.z(), 16, 'f', 7);
    file += QStringLiteral("    C%1%2%3\n")
              .arg(c.x(), 16, 'f', 7)
              .arg(c.y(), 16, 'f', 7)
              .arg(c.z(), 16, 'f', 7);

  } else {
    // @todo - this should look at the dimensions of the Molecule
    file += "    A     10.00000000    0.000000000    0.000000000\n";
    file += "    B     0.000000000    10.00000000    0.000000000\n";
    file += "    C     0.000000000    0.000000000    10.00000000\n";
  }
  file += "    &END CELL \n";

  if (m_molecule) {
    for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
      Core::Atom atom = m_molecule->atom(i);
      file += QString("    %1    %2    %3    %4\n")
                .arg(Core::Elements::symbol(atom.atomicNumber()), -3)
                .arg(atom.position3d().x(), 9, 'f', 5)
                .arg(atom.position3d().y(), 9, 'f', 5)
                .arg(atom.position3d().z(), 9, 'f', 5);
    }
  }
  if (gmethod == "DFT") {
    file += "  &DFT\n";
    file += "    BASIS_SET_FILE_NAME  BASIS_SET\n";
    file += "    POTENTIAL_FILE_NAME  GTH_POTENTIALS\n";
    if (ui.lsdcheckBox->isChecked())
      file += "    LSD TRUE\n";

    file += "    &QS\n";
    file += "      EPS_DEFAULT 1.0E-10\n";
    file += "    &END QS\n";
    file += QString("    LSD %1\n").arg(lsd);

    file += "    &MGRID\n";
    file += "      CUTOFF 280\n";
    file += "      COMMENSURATE\n";
    file += "    &END MGRID\n";

    file += "    &SCF\n";
    file += QString("      MAX_SCF %1\n").arg(maxSCF);
    file += QString("      EPS_SCF %1\n").arg(epsSCF);
    file += QString("      SCF_GUESS %1\n").arg(scfGuess);
    file += "      &OUTER_SCF\n";
    file += QString("        MAX_SCF %1\n").arg(outermaxSCF);
    file += QString("        EPS_SCF %1\n").arg(outerepsSCF);
    file += "      &END\n";
    file += "      &OT T\n";
    file += QString("        MINIMIZER %1\n").arg(otMinimizer);
    file += "        N_DIIS 7\n";
    file += "      &END OT\n";

    file += "    &END SCF\n";

    file += "    &XC\n";
    file += QString("      &XC_FUNCTIONAL %1\n").arg(functional);
    file += "      &END XC_FUNCTIONAL\n";
    file += "    &END XC\n";

    file += "  &END DFT\n";
    file += "  &PRINT\n";
    file += "    &FORCES ON\n";
    file += "    &END FORCES\n";
    file += "  &END PRINT\n";
  } else if (gmethod == "FIST") {

    file += "    &TOPOLOGY\n";
    file += "      CHARGE_BETA\n";
    file += "      CONNECTIVITY AMBER\n";
    file +=
      "      CONN_FILE_NAME ! Add file name that contains connectivity data\n";
    file += "    &END TOPOLOGY \n";

    file += "    &PRINT\n";
    file += "      &TOPOLOGY_INFO\n";
    file += "        AMBER_INFO\n";
    file += "      &END\n";
    file += "    &END \n";
    file += "  &END SUBSYS\n";

    file += "  &MM\n";

    file += "    &FORCEFIELD\n";
    file += "      PARM_FILE_NAME ! Add file name that contains force field "
            "parameters\n";
    file += "      PARMTYPE AMBER\n";

    file += "      &SPLINE\n";
    file += QString("        EMAX_SPLINE %1\n").arg(emaxSpline);
    file += QString("        RCUT_NB %1\n").arg(rcutnb);
    file += "      &END SPLINE\n";
    file += "    &END FORCEFIELD\n";

    file += "    &POISSON\n";
    file += "      &EWALD\n";
    file += QString("        EWALD_TYPE %1\n").arg(ewaldtype);
    file += QString("        ALPHA %1\n").arg(ewaldalpha);
    file += QString("        GMAX %1\n").arg(ewaldgmax);
    file += "      &END EWALD\n";
    file += "    &END POISSON\n";

    file += "    &PRINT\n";
    file += "      &FF_INFO\n";
    file += "      $END\n";
    file += "      &FF_PARAMETER_FILE\n";
    file += "      &END\n";
    file += "    &END PRINT\n";

    file += "  &END MM\n";
  }

  file += " $END\n";

  ui.previewText->setText(file);
  ui.previewText->document()->setModified(false);
  updateOptionCache();
}

void Cp2kInputDialog::resetClicked()
{
  setBasicDefaults();
  updatePreviewText();
}

void Cp2kInputDialog::defaultsClicked()
{
  setBasicDefaults();
  updatePreviewText();
}

void Cp2kInputDialog::generateClicked()
{
  QSettings settings;
  QString fileName =
    (ui.baseNameEdit->text().isEmpty() ? ui.baseNameEdit->placeholderText()
                                       : ui.baseNameEdit->text()) +
    ".inp";
  QString targetFile =
    settings.value("cp2kInput/outputDirectory", QDir::homePath()).toString();
  targetFile =
    QDir(QFileInfo(targetFile).absoluteDir()).absoluteFilePath(fileName);

  fileName =
    QFileDialog::getSaveFileName(this, tr("Save CP2K input file"), targetFile);

  // User cancel:
  if (fileName.isNull())
    return;

  settings.setValue("cp2kInput/outputDirectory", fileName);

  QFile file(fileName);
  bool success = false;
  if (file.open(QFile::WriteOnly | QFile::Text)) {
    if (file.write(ui.previewText->toPlainText().toLatin1()) > 0) {
      success = true;
    }
    file.close();
  }

  if (!success) {
    QMessageBox::critical(this, tr("Output Error"),
                          tr("Failed to write to file %1.").arg(fileName));
  }
}

void Cp2kInputDialog::computeClicked()
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
  job.setProgram("CP2K");
  job.setDescription(description);
  job.setInputFile(QString("%1.inp").arg(fileNameBase),
                   ui.previewText->toPlainText());

  MoleQueueDialog::SubmitStatus submitStatus =
    MoleQueueDialog::submitJob(this, tr("Submit CP2K Calculation"), job,
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

void Cp2kInputDialog::updateTitlePlaceholder()
{
  ui.titleEdit->setPlaceholderText(generateJobTitle());
}

} // end namespace QtPlugins
} // end namespace Avogadro
