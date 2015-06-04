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
//#include "gamesshighlighter.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/molequeue/molequeuedialog.h>
#include <avogadro/molequeue/molequeuemanager.h>

#include <molequeue/client/jobobject.h>
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

#include <vector>
#include <map>

using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;
using MoleQueue::JobObject;

namespace Avogadro {
namespace QtPlugins {

enum CalculateOption {
  CalculateEnergy = 0,
  CalculateEnergyAndForces,
  CalculateMolecularDynamics,
  CalculateGeometryOptimization,

  CalculateCount
};

enum FunctionalOption {
  FunctionalBLYP = 0,
  FunctionalBP,
  FunctionalHCTH120,
  FunctionalPADE,
  FunctionalPBE,

  FunctionalCount
};

enum BasisOption {
  BasisSZVGTH = 0,
  BasisDZVGTH,
  BasisDZVPGTH,
  BasisTZVPGTH,
  BasisTZV2PGTH,

  BasisCount
};

enum StateOption {
  StateGas = 0,
  StateWater,

  StateCount
};

enum MethodOption {
  DFT = 0,
  MolecularMechanics,
  HybridQuantumClassical,

  MethodCount
};

enum ChargeOption {
  ChargeDication = 0,
  ChargeCation,
  ChargeNeutral,
  ChargeAnion,
  ChargeDianion,

  ChargeCount
};

Cp2kInputDialog::Cp2kInputDialog(QWidget *parent_, Qt::WindowFlags f)
  : QDialog( parent_, f ),
    m_molecule(NULL),
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

Cp2kInputDialog::~Cp2kInputDialog()
{
}

void Cp2kInputDialog::setMolecule(QtGui::Molecule *mol)
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

void Cp2kInputDialog::showEvent(QShowEvent *e)
{
  QWidget::showEvent(e);

  // Update the preview text if an update was requested while hidden. Use a
  // single shot to allow the dialog to show before popping up any warnings.
  if (m_updatePending)
    QTimer::singleShot(0, this, SLOT(updatePreviewText()));
}

void Cp2kInputDialog::connectBasic()
{
  connect(ui.titleEdit, SIGNAL( textChanged(QString)),
          this, SLOT(updatePreviewText()));
  connect( ui.calculateCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect(ui.calculateCombo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(updateTitlePlaceholder()));
  connect( ui.functionalCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect(ui.functionalCombo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(updateTitlePlaceholder()));
  connect( ui.basisCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect(ui.basisCombo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(updateTitlePlaceholder()));
  connect( ui.stateCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect( ui.methodCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect( ui.chargeCombo, SIGNAL( currentIndexChanged( int ) ),
           this, SLOT( updatePreviewText() ) );
  connect( ui.emaxSplineSpin, SIGNAL( valueChanged( int ) ),
           this, SLOT( updatePreviewText() ) );

}

void Cp2kInputDialog::connectPreview()
{
}

void Cp2kInputDialog::connectButtons()
{
  connect( ui.resetAllButton, SIGNAL(clicked()), SLOT(resetClicked()));
  connect( ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect( ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect( ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect( ui.closeButton, SIGNAL(clicked()), SLOT(close()));
}

void Cp2kInputDialog::buildOptions()
{
  buildCalculateOptions();
  buildFunctionalOptions();
  buildBasisOptions();
  buildStateOptions();
  buildMethodOptions();
  buildChargeOptions();
}

void Cp2kInputDialog::updateOptionCache()
{
  m_optionCache.clear();
  m_optionCache.insert(ui.calculateCombo, ui.calculateCombo->currentIndex());
  m_optionCache.insert(ui.functionalCombo, ui.functionalCombo->currentIndex());
  m_optionCache.insert(ui.basisCombo, ui.basisCombo->currentIndex());
  m_optionCache.insert(ui.stateCombo, ui.stateCombo->currentIndex());
  m_optionCache.insert(ui.methodCombo, ui.methodCombo->currentIndex());
  m_optionCache.insert(ui.chargeCombo, ui.chargeCombo->currentIndex());

}

void Cp2kInputDialog::restoreOptionCache()
{
  foreach (QComboBox *combo, m_optionCache.keys()) {
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

void Cp2kInputDialog::buildStateOptions()
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

void Cp2kInputDialog::buildChargeOptions()
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

void Cp2kInputDialog::setBasicDefaults()
{
  ui.titleEdit->setText(QString());
  ui.calculateCombo->setCurrentIndex( CalculateEnergy );
  ui.functionalCombo->setCurrentIndex( FunctionalBLYP );
  ui.basisCombo->setCurrentIndex( BasisSZVGTH );
  ui.stateCombo->setCurrentIndex( StateGas );
  ui.methodCombo->setCurrentIndex( DFT );
  ui.chargeCombo->setCurrentIndex( ChargeNeutral );


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
	  std::map<char,int> valencee;

	  valencee['H'] = 1;
	  valencee['He'] = 2;
	  valencee['Li'] = 3;
	  valencee['Be'] = 4;
	  valencee['B'] = 3;
	  valencee['C'] = 4;
	  valencee['N'] = 5;
	  valencee['O'] = 6;
	  valencee['F'] = 7;
	  valencee['Ne'] = 8;
	  valencee['Na'] = 9;
	  valencee['Mg'] = 10;
	  valencee['Al'] = 3;
	  valencee['Si'] = 4;
	  valencee['P'] = 5;
	  valencee['S'] = 6;
	  valencee['Cl'] = 7;
	  valencee['Ar'] = 8;
	  valencee['K'] = 9;
	  valencee['Ca'] = 10;
	  valencee['Sc'] = 11;
	  valencee['Ti'] = 12;
	  valencee['V'] = 13;
	  valencee['Cr'] = 14;
	  valencee['Mn'] = 15;
	  valencee['Fe'] = 16;
	  valencee['Co'] = 17;
	  valencee['Ni'] = 18;
	  valencee['Cu'] = 11;
	  valencee['Zn'] = 12;
	  valencee['Ga'] = 13;
	  valencee['Ge'] = 4;
	  valencee['As'] = 5;
	  valencee['Se'] = 6;
	  valencee['Br'] = 7;
	  valencee['Kr'] = 8;
	  valencee['As'] = 5;
	  valencee['Sr'] = 10;
	  valencee['Y'] = 11;
	  valencee['Zr'] = 12;
	  valencee['Mo'] = 14;
	  valencee['Ru'] = 16;
	  valencee['Rh'] = 17;
	  valencee['Pd'] = 18;
	  valencee['Ag'] = 11;
	  valencee['In'] = 13;
	  valencee['Sb'] = 5;
	  valencee['Te'] = 6;
	  valencee['I'] = 7;
	  valencee['Ba'] = 10;
	  valencee['W'] = 14;
	  valencee['Au'] = 11;
	  valencee['Bi'] = 15;


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
    int response =
        QMessageBox::question(this, tr("Overwrite modified input file?"),
                              message, QMessageBox::Yes | QMessageBox::No,
                              QMessageBox::No);
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
  BasisOption basis(
        static_cast<BasisOption>(ui.basisCombo->currentIndex()));
  StateOption state(
        static_cast<StateOption>(ui.stateCombo->currentIndex()));
  MethodOption method(
        static_cast<MethodOption>(ui.methodCombo->currentIndex()));
  ChargeOption charge(
        static_cast<ChargeOption>(ui.chargeCombo->currentIndex()));

  QString emaxSpline = QString::number(ui.emaxSplineSpin->value());

  // Disable basis selection for semiempirical methods.
  //ui.basisCombo->setEnabled(theory != TheoryAM1 && theory != TheoryPM3);

  // Generate text.
  //   Variables:
  QString runTyp;
  QString scfTyp;
  QString gbasis;
  QString gfunc;
  QString gmethod;
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
  case CalculateEnergy:
    runTyp = "ENERGY";
    break;
  case CalculateEnergyAndForces:
    runTyp = "ENERGY_FORCE";
    //statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n";
    break;
  case CalculateMolecularDynamics:
    runTyp = "MOLECULAR_DYNAMICS";
   // statPt = " $STATPT OPTTOL=0.0001 NSTEP=20 $END\n";
    break;
  case CalculateGeometryOptimization:
    runTyp = "GEO_OPT";
    //force = " $FORCE METHOD=ANALYTIC VIBANL=.TRUE. $END\n";
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

  switch (state) {
  case StateGas:
    break;
  case StateWater:
    pcm = " $PCM SOLVNT=WATER $END\n";
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
  /*
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

*/
 file += "&GLOBAL\n";
 file += QString("  PROJECT %1\n").arg(title);
 //file += QString("  EMAX_SPLINE %1\n").arg(emaxSpline);

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
     for (int i = 0; i<atomList.size();i++) {
    	 if (atomList.at(i) == atom.atomicNumber()) {
    		 inlist = false;
    		 break;
    	 }
    	 else{
    		 inlist = true;
    	 }
     }
     if (inlist){
    	 atomList.push_back(atom.atomicNumber());
     file += QString("    &KIND %1\n").arg(Core::Elements::symbol(atom.atomicNumber()));
     file += QString("        ELEMENT %1\n").arg(Core::Elements::symbol(atom.atomicNumber()));
     file += QString("        BASIS_SET %1\n").arg(gbasis);
     //file += QString("        POTENTIAL GTH-%1-q%2\n").arg(gfunc).arg(gvalence);
     }
   }
 }

 file += "    &CELL\n";
 file += "    A     10.00000000    0.000000000    0.000000000\n";
 file += "    B     0.000000000    10.00000000    0.000000000\n";
 file += "    C     0.000000000    0.000000000    10.00000000\n";
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
if(gmethod == "DFT") {
  file += "  &DFT\n";
  file += "    BASIS_SET_FILE_NAME  BASIS_SET\n";
  file += "    POTENTIAL_FILE_NAME  GTH_POTENTIALS\n";

  file += "    &QS\n";
  file += "      EPS_DEFAULT 1.0E-10\n";
  file += "    &END QS\n";
/*
  file += "    &MGRID\n";
  file += "      NGRIDS "+str(ngrids)+"\n"
  file += "      CUTOFF "+str(cutoff)+"\n"
  file += "      REL_CUTOFF "+str(rel_cutoff)+"\n"
  file += "    &END MGRID\n";

  file += "    &XC\n";
  file += "      &XC_FUNCTIONAL "+functional+"\n";
  file += "      &END XC_FUNCTIONAL\n";
  file += "    &END XC\n";
*/
  file += "    &SCF\n";
  file += "      SCF_GUESS ATOMIC\n";
  file += "      EPS_SCF 1.0E-7\n";
  file += "      MAX_SCF 300\n";
  file += "      &DIAGONALIZATION\n";
  file += "        ALGORITHM STANDARD\n";
  file += "      &END DIAGONALIZATION\n";
  file += "      &MIXING\n";
  file += "        METHOD BROYDEN_MIXING\n";
  file += "        ALPHA 0.4\n";
  file += "        NBROYDEN 8\n";
  file += "      &END MIXING\n";

  file += "    &END SCF\n";

  file += "  &END DFT\n";
  file += "  &PRINT\n";
  file += "    &FORCES ON\n";
  file += "    &END FORCES\n";
  file += "  &END PRINT\n";
}
else if(gfunc == "FIST") {

	 file += "    &TOPOLOGY\n";
	    file += "      CHARGE_BETA\n";
	    file += "      CONNECTIVITY AMBER\n";
	    file += "      CONN_FILE_NAME ! Add file name that contains connectivity data\n";
	    file += "    &END TOPOLOGY \n";

	    file += "    &PRINT\n";
	    file += "      &TOPOLOGY_INFO\n";
	    file += "        AMBER_INFO\n";
	    file += "      &END\n";
	    file += "    &END \n";
	    file += "  &END SUBSYS\n";

	    file += "  &MM\n";

	    file += "    &FORCEFIELD\n";
	    file += "      ! Add file name that contains force field parameters\n";
	    file += "      PARMTYPE AMBER\n";

	    file += "      &SPLINE\n";
	    file += "        EMAX_SPLINE 10000\n";
	    file += "      &END SPLINE\n";
	    file += "    &END FORCEFIELD\n";

	    file += "    &POISSON\n";
	    file += "      &EWALD\n";
	    file += "        EWALD_TYPE SPME\n";
	    file += "        ALPHA .36\n";
	    file += "        GMAX 128\n";
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
  QString fileName = (ui.baseNameEdit->text().isEmpty()
                      ? ui.baseNameEdit->placeholderText()
                      : ui.baseNameEdit->text()) + ".inp";
  QString targetFile = settings.value("cp2kInput/outputDirectory",
                                     QDir::homePath()).toString();
  targetFile = QDir(QFileInfo(targetFile).absoluteDir()).absoluteFilePath(
        fileName);

  fileName = QFileDialog::getSaveFileName(this, tr("Save CP2K input file"),
                                          targetFile);

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
  MoleQueueManager &mqManager = MoleQueueManager::instance();
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
      ? ui.baseNameEdit->placeholderText() : ui.baseNameEdit->text();

  JobObject job;
  job.setProgram("CP2K");
  job.setDescription(description);
  job.setInputFile(QString("%1.inp").arg(fileNameBase),
                   ui.previewText->toPlainText());

  MoleQueueDialog::SubmitStatus submitStatus =
      MoleQueueDialog::submitJob(this,
                                 tr("Submit CP2K Calculation"),
                                 job, MoleQueueDialog::WaitForSubmissionResponse
                                 | MoleQueueDialog::SelectProgramFromTemplate);

  switch (submitStatus) {
  default:
  case MoleQueueDialog::SubmissionSuccessful:
  case MoleQueueDialog::SubmissionFailed:
  case MoleQueueDialog::SubmissionAttempted:
  case MoleQueueDialog::SubmissionAborted:
    // The dialog handles these cases adequately, we don't need to do anything.
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
