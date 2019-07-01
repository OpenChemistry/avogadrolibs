/**********************************************************************
  SimuneAntInputDialog - Dialog for generating Gaussian input decks

  Copyright (C) 2008 Marcus D. Hanwell
  Copyright (C) 2008 Michael Banck

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Avogadro is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Avogadro is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
  02110-1301, USA.
 **********************************************************************/

#include "simuneantinputdialog.h"
#include "simuneanthighlighter.h"

//------ OLD INCLUDES IN AVOGADRO2 --------
//#include <avogadro/molecule.h>
//#include <avogadro/atom.h>

//#include <openbabel/mol.h>
//--- END OF OLD INCLUDES IN AVOGADRO2 -----

//------  NEW INCLUDES IN AVOGADRO2 --------
#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/crystaltools.h>
#include <avogadro/core/vector.h>

#include <avogadro/qtgui/molecule.h>
#include <avogadro/molequeue/molequeuedialog.h>
#include <avogadro/molequeue/molequeuemanager.h>

#include <molequeue/client/jobobject.h>
#include <qjsonarray.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QTimer>

//--- END OF NEW INCLUDES IN AVOGADRO2 -----

#include <QString>
//#include <QStringLiteral>
#include <QTextStream>
#include <QFileDialog>
#include <QMessageBox>
#include <QShowEvent>
#include <QSettings>
#include <QDebug>
#include <QProcess>
#include <QScrollBar>
#include "qmath.h" // ADDED BY C.SALGADO TO USE: INT QFLOOR(DOUBLE)

//using namespace OpenBabel;

using Avogadro::MoleQueue::MoleQueueDialog;
using Avogadro::MoleQueue::MoleQueueManager;
using MoleQueue::JobObject;

//-------------------------------------------------------------------------------
//-------- I TAKE THIS PART FROM COORDINATEEDITORDIALOG.CPP ---------------------
//-------- TO USE "QVector<Atomstruc> atoms" IN THE SAME MANNER -----------------
//-------- USED IN AVOGADRO-QT4 -------------------------------------------------
//-------------------------------------------------------------------------------
using Avogadro::QtGui::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Vector3;

namespace {

// Ensure a cross-platform monospaced font
#ifdef Q_WS_X11
static const QString EDITOR_FONT = "Monospace";
#else // Windows and Mac
static const QString EDITOR_FONT = "Courier";
#endif

// Various integer constants.
enum {
  CustomPreset = 0
};

// Distance unit indices -- keep in sync with the .ui file.
enum DistanceUnitIndex {
  Angstrom = 0,
  Bohr
};

// Types of tokens, used while parsing.
enum TokenType {
  Integer = 0,
  Double,
  String
};

// Some frequently used regexes:
static const QRegExp TOKEN_SEPARATOR("[\\s,;]+");
static const QRegExp VALID_TOKEN("[^\\s,;]+");
static const QRegExp INT_CHECKER("(:?[+-])?\\d+");
static const QRegExp DOUBLE_CHECKER(
    "(:?[+-])?"                   // Leading sign
    "(:?"                         // Must match one of the following:
    "\\d*\\.\\d*"                 // Fractional part
    "|"                           // or
    "\\d+[Ee](:?[+-])?\\d+"       // Exponential part
    "|"                           // or
    "\\d*\\.\\d*"                 // Fractional part and
    "[Ee](:?[+-])?\\d+"           // Exponential part
    ")");

struct AtomStruct {
  unsigned char atomicNumber;
  Vector3 pos;
};

} // end anon namespace
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------

namespace Avogadro {
namespace QtPlugins {

//-------------------------------------------------------------------------------
//-------- I TAKE THIS PART FROM COORDINATEEDITORDIALOG.CPP ---------------------
//-------- CONSTRUCTING CLASS VALIDATESTORAGE -----------------------------------
//-------- TO USE "QVector<Atomstruc> atoms" IN THE SAME MANNER -----------------
//-------- USED IN AVOGADRO-QT4 -------------------------------------------------
//-------------------------------------------------------------------------------
// Storage class used to hold state while validating input.
class SimuneAntInputDialog::ValidateStorage
{
public:
  ValidateStorage()
    : isValidating(false),
      restartWhenFinished(false),
      collectAtoms(false),
      convertDistance(false),
      latticePositions(false),
      distanceConversion(1.f)
  {}

  bool isValidating;
  bool restartWhenFinished;
  bool collectAtoms;
  bool convertDistance;
  bool latticePositions;
  float distanceConversion;

  // Format specification
  QString spec;

  // Text cursors
  QTextCursor lineCursor;
  QTextCursor tokenCursor;

  // Accumulate atom data
  QVector<AtomStruct> atoms;
};
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------

//-------------------------------------------------------------------------------
enum CalculateOption {
  CalculateSinglePoint = 0,
  CalculateEquilibriumGeometry,
  CalculateTransitionState,
  CalculateFrequencies,

  CalculateCount
};

enum TheoryOption {
  TheoryAM1 = 0,
  TheoryPM3,
  TheoryRHF,
  TheoryB3LYP,
  TheoryMP2,
  TheoryCCSDT,

  TheoryCount
};

enum BasisOption {
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

enum StateOption {
  StateGas = 0,
  StateWater,

  StateCount
};

enum MultiplicityOption {
  MultiplicitySinglet = 0,
  MultiplicityDoublet,
  MultiplicityTriplet,

  MultiplicityCount
};

enum ChargeOption {
  ChargeDication = 0,
  ChargeCation,
  ChargeNeutral,
  ChargeAnion,
  ChargeDianion,

  ChargeCount
};
//-------------------------------------------------------------------------------
void SimuneAntInputDialog::writeSettings(QSettings &settings) const
{
  qDebug()<<"I am in writeSettings";
  settings.setValue("gaussian/CalcType", ui.calculationCombo->currentIndex());
  settings.setValue("gaussian/Procs", ui.procSpin->value());
  settings.setValue("gaussian/Theory", ui.theoryCombo->currentIndex());
  settings.setValue("gaussian/Basis", ui.basisMolecCombo->currentIndex());
  settings.setValue("gaussian/Output", ui.outputCombo->currentIndex());
  settings.setValue("gaussian/Chk", ui.checkpointCheck->isChecked());
  settings.setValue("gaussian/Coord", ui.coordCombo->currentIndex());
  //settings.setValue("gaussian/savepath", m_savePath);
}


void SimuneAntInputDialog::readSettings(QSettings &settings)
{
  qDebug()<<"I am in readsettings";
  setProcs(settings.value("ANT.G/Procs", 2).toInt());
  ui.procSpin->setValue(settings.value("ANT.G/Procs", 2).toInt());
  setCalculation(settings.value("ANT.G/CalcType", 0).toInt());
  ui.calculationCombo->setCurrentIndex(settings.value("ANT.G/CalcType", 0).toInt());
  setTheory(settings.value("ANT.G/Theory", 0).toInt());
  ui.theoryCombo->setCurrentIndex(settings.value("ANT.G/Theory", 0).toInt());
  //setBasis(settings.value("ANT.G/Basis", 2).toInt());
  //ui.basisMolecCombo->setCurrentIndex(settings.value("ANT.G/Basis", 2).toInt());
  setOutput(settings.value("ANT.G/Output", 0).toInt());
  ui.outputCombo->setCurrentIndex(settings.value("ANT.G/Output", 0).toInt());
  setChk(settings.value("ANT.G/Chk", false).toBool());
  ui.checkpointCheck->setChecked(settings.value("ANT.G/Chk", false).toBool());
  setCoords(settings.value("ANT.G/Coord", 0).toInt());
  ui.coordCombo->setCurrentIndex(settings.value("ANT.G/Coord", 0).toInt());
  //m_savePath = settings.value("ANT.G/savepath").toString();

}

/*
  //SimuneAntInputDialog::SimuneAntInputDialog(QWidget *parent_, Qt::WindowFlags f)
  //  : InputDialog(parent_, f),
  SimuneAntInputDialog::SimuneAntInputDialog(QWidget *parent_, Qt::WindowFlags f)
    : QDialog( parent_, f ),
    m_calculationType(OPT),
    m_theoryType(B3LYP), m_basisType(B631Gd),
    m_procs(1), m_output(""), m_chk(false), m_coordType(CARTESIAN),
    m_dirty(false), m_warned(false), m_process(0), m_progress(0),
    m_molecule(NULL), // COPIED FROM GAMESSINPUTDIALOG
    //m_highlighter(NULL), // COPIED FROM GAMESSINPUTDIALOG
    m_updatePending(false), // COPIED FROM GAMESSINPUTDIALOG
    //m_molecule(0), // COPIED FROM INPUTDIALOG IN OLD AVOGADRO1
    m_title("Title"), // COPIED FROM INPUTDIALOG IN OLD AVOGADRO1
    m_multiplicity(1), m_charge(0), m_savePath("") // COPIED FROM INPUTDIALOG IN OLD AVOGADRO1
  {
    ui.setupUi(this);
    // Connect the GUI elements to the correct slots
    connect(ui.titleLine, SIGNAL(editingFinished()),
        this, SLOT(getTitle()));
    connect(ui.calculationCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setCalculation(int)));
    connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setTheory(int)));
    connect(ui.basisMolecCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setBasis(int)));
    connect(ui.multiplicitySpin, SIGNAL(valueChanged(int)),
        this, SLOT(setMultiplicity(int)));
    connect(ui.chargeSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setCharge(int)));
    connect(ui.procSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setProcs(int)));
    connect(ui.outputCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setOutput(int)));
    connect(ui.checkpointCheck, SIGNAL(stateChanged(int)),
        this, SLOT(setChk(int)));
    connect(ui.coordCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setCoords(int)));
    connect(ui.previewcomText, SIGNAL(textChanged()),
        this, SLOT(previewEdited()));
    connect(ui.generateButton, SIGNAL(clicked()),
        this, SLOT(generateClicked()));
    connect(ui.computeButton, SIGNAL(clicked()),
        this, SLOT(computeClicked()));
    connect(ui.resetButton, SIGNAL(clicked()),
        this, SLOT(resetClicked()));
    connect(ui.moreButton, SIGNAL(clicked()),
        this, SLOT(moreClicked()));
    connect(ui.enableFormButton, SIGNAL(clicked()),
        this, SLOT(enableFormClicked()));

    QSettings settings;
    readSettings(settings);

    // Generate an initial preview of the input deck
    updatePreviewText();
  }

  SimuneAntInputDialog::~SimuneAntInputDialog()
  {
      QSettings settings;
      writeSettings(settings);
  }
  */

  //------------------------------------------------------------------------------
  //------------------------------------------------------------------------------
  //---------- BEGIN OF CODE FROM AVOGADRO2 --------------------------------------
  //------------------------------------------------------------------------------
  //------------------------------------------------------------------------------
  SimuneAntInputDialog::SimuneAntInputDialog(QWidget *parent_, Qt::WindowFlags f)
    : QDialog( parent_, f ),
      m_calculationType(SP),
      m_theoryType(lsda), m_basisType(minimal6s),
      m_procs(1), m_output(""), m_chk(false), m_coordType(CARTESIAN),
      m_dirty(false), m_warned(false), m_process(0), m_progress(0),
      m_molecule(NULL),
      m_highlighter(NULL),
      m_updatePending(false),
      m_title("Title"), // COPIED FROM INPUTDIALOG IN OLD AVOGADRO1
      m_multiplicity(1), m_charge(0), m_savePath(""), // COPIED FROM INPUTDIALOG IN OLD AVOGADRO1
      m_validate(new ValidateStorage) // COPIED FROM COORDINATEEDITOR.CPP IN NEW AVOGADRO2 BUT TO MATCH m_molecule()->atoms() PROPERTY FROM OLD AVOGADRO-QT4.
  {
    ui.setupUi(this);
    m_highlighter = new SimuneAntHighlighter(ui.previewcomText->document());

    //buildOptions(); // DELETED BECAUSE IT IS USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN

    qDebug() << "I am in SimuneAntInputDialog and I modified m_validate!!!";

    connectBasic();
    connectPreview();
    connectButtons();
    connectIni();

    //setMolecule(m_molecule);

    setBasicDefaults();
    setIniDefaults();

    QSettings settings;
    readSettings(settings);

    updatePreviewComText();
    updatePreviewIniText();
  }

  SimuneAntInputDialog::~SimuneAntInputDialog()
  {
      QSettings settings;
      writeSettings(settings);
  }

  void SimuneAntInputDialog::setMolecule(QtGui::Molecule *mol)
  {
    qDebug()<<"I am in setMolecule";
    if (mol == m_molecule)
      return;

    if (m_molecule)
      m_molecule->disconnect(this);

    m_molecule = mol;

    //--------------------- ADDED FROM AVOGADRO1 ------------------------------------------------
    // Update the preview text whenever atoms are changed
    //connect(m_molecule, SIGNAL(atomRemoved(Atom *)),
    //        this, SLOT(updatePreviewText()));
    //connect(m_molecule, SIGNAL(atomAdded(Atom *)),
    //        this, SLOT(updatePreviewText()));
    //connect(m_molecule, SIGNAL(atomUpdated(Atom *)),
    //        this, SLOT(updatePreviewText()));
    //------------------- END ADDED FROM AVOGADRO1 ----------------------------------------------

    connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewComText()));
    connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewIniText()));
    //connect(mol, SIGNAL(changed(unsigned int)), SLOT(updateTitlePlaceholder()));
    connect(mol, SIGNAL(changed(unsigned int)), SLOT(updateTitle()));

    //updateTitlePlaceholder();
    updateTitle();
    updatePreviewComText();
    updatePreviewIniText();
  }

  void SimuneAntInputDialog::showEvent(QShowEvent *e)
  {
      qDebug()<<"I am in showEvent";
    QWidget::showEvent(e);

    // Update the preview text if an update was requested while hidden. Use a
    // single shot to allow the dialog to show before popping up any warnings.
    if (m_updatePending)
      QTimer::singleShot(0, this, SLOT(updatePreviewComText()));

    if ((pathToGaussian().isEmpty()) && (pathToG03().isEmpty())){ // ADDED FROM AVOGADRO1.
      //ui.computeButton->hide(); // ADDED FROM AVOGADRO1.
      ui.computeButton->setDisabled(true);
    }else{ // ADDED FROM AVOGADRO1.
      ui.computeButton->show(); // ADDED FROM AVOGADRO1.
      ui.computeButton->setEnabled(true);
    }
  }

  void SimuneAntInputDialog::connectBasic()
  {
      qDebug()<<"I am in connectBasic";
    //connect(ui.titleEdit, SIGNAL(textChanged(QString)),
    //        this, SLOT(updatePreviewText()));
    connect(ui.titleLine, SIGNAL(textChanged(QString)),
                  this, SLOT(updatePreviewComText()));
    connect(ui.titleLine, SIGNAL(editingFinished()),
        this, SLOT(getTitle()));
    //connect( ui.calculateCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS NOT NECESSARY BECAUSE IS WRITTEN BELOW CONNECTED TO setCalculation(int)
    //connect(ui.calculationCombo, SIGNAL(currentIndexChanged(int)),
    //        this, SLOT(updateTitlePlaceholder()));
    connect(ui.calculationCombo, SIGNAL(currentIndexChanged(int)),
            this, SLOT(updateTitle()));
    //connect( ui.theoryCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS NOT NECESSARY BECAUSE IS WRITTEN BELOW CONNECTED TO setTheory(int)
    //connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)),
    //        this, SLOT(updateTitlePlaceholder()));
    connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)),
            this, SLOT(updateTitle()));
    //connect( ui.basisMolecCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS NOT NECESSARY BECAUSE IS WRITTEN BELOW CONNECTED TO setBasis(int)
    //connect(ui.basisMolecCombo, SIGNAL(currentIndexChanged(int)),
    //        this, SLOT(updateTitlePlaceholder()));
    //connect( ui.stateCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
    //connect( ui.multiplicityCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
    //connect( ui.chargeCombo, SIGNAL( currentIndexChanged( int ) ),
    //         this, SLOT( updatePreviewText() ) ); // THIS IS USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.

    //---------------------------------------------------------------------------------------
    connect(ui.titleLine, SIGNAL(editingFinished()),
        this, SLOT(getTitle()));
    connect(ui.calculationCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setCalculation(int)));
    connect(ui.theoryCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setTheory(int)));
    //connect(ui.basisMolecCombo, SIGNAL(currentIndexChanged(int)),
    //    this, SLOT(setBasis(int)));
    //connect(ui.basisMolecCombo, SIGNAL(currentIndexChanged(int)),
    //        this, SLOT(setMolecBasis(int)));
    //connect(ui.basisMolecCombo, SIGNAL(currentIndexChanged(int)),
    //        this, SLOT(getLoadFullBasisType(int)));
    connect(ui.multiplicitySpin, SIGNAL(valueChanged(int)),
        this, SLOT(setMultiplicity(int)));
    connect(ui.chargeSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setCharge(int)));
    connect(ui.procSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setProcs(int)));
    connect(ui.outputCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setOutput(int)));
    connect(ui.checkpointCheck, SIGNAL(stateChanged(int)),
        this, SLOT(setChk(int)));
    connect(ui.checkUseAntGBox, SIGNAL(stateChanged(int)),
        this, SLOT(setUseAntG(int)));
    connect(ui.checkUseAntGl101, SIGNAL(stateChanged(int)),
        this, SLOT(setUseAntGl101(int)));
    connect(ui.checkUseAntGl103, SIGNAL(stateChanged(int)),
        this, SLOT(setUseAntGl103(int)));
    connect(ui.checkUseAntGl502, SIGNAL(stateChanged(int)),
        this, SLOT(setUseAntGl502(int)));
    connect(ui.checkUseAntGl703, SIGNAL(stateChanged(int)),
        this, SLOT(setUseAntGl703(int)));
    connect(ui.coordCombo, SIGNAL(currentIndexChanged(int)),
        this, SLOT(setCoords(int)));
    connect(ui.previewcomText, SIGNAL(textChanged()),
        this, SLOT(previewEdited()));
    //connect(ui.generateButton, SIGNAL(clicked()),
    //    this, SLOT(generateClicked()));
    //connect(ui.computeButton, SIGNAL(clicked()),
    //    this, SLOT(computeClicked()));
    //connect(ui.computeButton, SIGNAL(clicked()),
    //    this, SLOT(computeClickedAnt()));
    //connect(ui.submitButton, SIGNAL(clicked()),
    //    this, SLOT(submitClicked()));
    //connect(ui.resetButton, SIGNAL(clicked()),
    //    this, SLOT(resetClicked()));
    //connect(ui.moreButton, SIGNAL(clicked()),
    //    this, SLOT(moreClicked()));
    //connect(ui.enableFormButton, SIGNAL(clicked()),
    //    this, SLOT(enableFormClicked()));
    connect(ui.scfConverSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setscfConver(int)));

    connect(ui.checkUHF, SIGNAL(stateChanged(int)),
        this, SLOT(setUHF(int)));
    connect(ui.checkglobalnosymm, SIGNAL(stateChanged(int)),
        this, SLOT(setglobalnosymm(int)));
    connect(ui.checkscfnosymm, SIGNAL(stateChanged(int)),
        this, SLOT(setscfnosymm(int)));
    connect(ui.checkscfnodamp, SIGNAL(stateChanged(int)),
        this, SLOT(setscfnodamp(int)));
    connect(ui.checkscfnovaracc, SIGNAL(stateChanged(int)),
        this, SLOT(setscfnovaracc(int)));

    connect(ui.scfMaxCycleSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setscfMaxCycleSpin(int)));
    connect(ui.scfMaxCycleSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setscfMaxCycleSpin(int)));


    connect(ui.checkOpt, SIGNAL(stateChanged(int)),
        this, SLOT(setOpt(int)));
    //connect(ui.checkOpt, SIGNAL(isChecked(bool)),
    //        this, SLOT(setOpt(bool)));
    connect(ui.checkForce, SIGNAL(stateChanged(int)),
        this, SLOT(setForce(int)));

    connect(ui.optmaxcyclesSpin, SIGNAL(valueChanged(int)),
        this, SLOT(setoptmaxcycles(int)));

    connect(ui.optAccuracyCombo, SIGNAL(currentIndexChanged(int)),
            this, SLOT(setoptAccuracy(int)));

  }

  void SimuneAntInputDialog::connectIni()
  {
      qDebug()<<"I am in connectIni";
      connect(ui.type1Combo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(settype1Combo(int)));
      connect(ui.type2Combo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(settype2Combo(int)));
      connect(ui.blpar1Combo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(setblpar1Combo(int)));
      connect(ui.blpar2Combo, SIGNAL(currentIndexChanged(int)),
          this, SLOT(setblpar2Combo(int)));

      connect(ui.hamiltonCheck, SIGNAL(stateChanged(int)),
          this, SLOT(sethamiltonCheck(int)));
      connect(ui.mullikenCheck, SIGNAL(stateChanged(int)),
          this, SLOT(setmullikenCheck(int)));
      connect(ui.leaddosCheck, SIGNAL(stateChanged(int)),
          this, SLOT(setleaddosCheck(int)));
      connect(ui.htransmCheck, SIGNAL(stateChanged(int)),
          this, SLOT(sethtransmCheck(int)));

      connect(ui.alphaSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setalphaSpin(double)));
      connect(ui.overlapSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setoverlapSpin(double)));
      connect(ui.biasvoltSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setbiasvoltSpin(double)));
      connect(ui.qexcessSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setqexcessSpin(double)));
      connect(ui.fermistartSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setfermistartSpin(double)));
      connect(ui.estepSpin, SIGNAL(valueChanged(double)),
          this, SLOT(setestepSpin(double)));
      connect(ui.ew1Spin, SIGNAL(valueChanged(double)),
          this, SLOT(setew1Spin(double)));
      connect(ui.ew2Spin, SIGNAL(valueChanged(double)),
          this, SLOT(setew2Spin(double)));

      connect(ui.paccSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setpaccSpin(int)));
      connect(ui.chargeaccSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setchargeaccSpin(int)));
      connect(ui.fermiaccSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setfermiaccSpin(int)));
      connect(ui.selfaccSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setselfaccSpin(int)));
      connect(ui.etaSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setetaSpin(int)));
      connect(ui.slSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setslSpin(int)));
      /*
      connect(ui.ssmSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setssmSpin(int)));
      */
      connect(ui.swoffsplSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setswoffsplSpin(int)));

      connect(ui.natomel1Spin, SIGNAL(valueChanged(int)),
          this, SLOT(setnatomel1Spin(int)));
      connect(ui.natomel2Spin, SIGNAL(valueChanged(int)),
          this, SLOT(setnatomel2Spin(int)));
      connect(ui.nembed1Spin, SIGNAL(valueChanged(int)),
          this, SLOT(setnembed1Spin(int)));
      connect(ui.nembed2Spin, SIGNAL(valueChanged(int)),
          this, SLOT(setnembed2Spin(int)));
      connect(ui.natomel1Spin, SIGNAL(valueChanged(int)),
          this, SLOT(setnatomel1Spin(int)));
      connect(ui.nspinlockSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setnspinlockSpin(int)));
      connect(ui.nalphaSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setnalphaSpin(int)));
      connect(ui.nbetaSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setnbetaSpin(int)));
      connect(ui.ldosbegSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setldosbegSpin(int)));
      connect(ui.ldosendSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setldosendSpin(int)));
      connect(ui.rtmbegSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setrtmbegSpin(int)));
      connect(ui.rtmendSpin, SIGNAL(valueChanged(int)),
          this, SLOT(setrtmendSpin(int)));

      connect(ui.previewiniText, SIGNAL(textChanged()),
          this, SLOT(previewIniEdited()));
  }

  void SimuneAntInputDialog::connectPreview()
  {
      qDebug()<<"I am in connectPreview";
  }

  void SimuneAntInputDialog::connectButtons()
  {
      qDebug()<<"I am in connectButtons";
    //connect( ui.resetAllButton, SIGNAL(clicked()), SLOT(resetClicked()));
    connect( ui.resetButton, SIGNAL(clicked()), SLOT(resetClicked()));
    connect( ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
    connect( ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
    //connect( ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
    connect( ui.computeButton, SIGNAL(clicked()), SLOT(computeClickedAnt()));
    connect( ui.submitButton, SIGNAL(clicked()), SLOT(submitClicked()));
    connect( ui.closeButton, SIGNAL(clicked()), SLOT(close()));

    connect(ui.resetButton, SIGNAL(clicked()),
        this, SLOT(resetClicked()));
    connect(ui.moreButton, SIGNAL(clicked()),
        this, SLOT(moreClicked()));
    //connect(ui.enableFormButton, SIGNAL(clicked()),
    //    this, SLOT(enableFormClicked()));
  }

  void SimuneAntInputDialog::updateOptionCache()
  {
      qDebug()<<"I am in updateOptionCache";
    m_optionCache.clear();
    m_optionCache.insert(ui.calculationCombo, ui.calculationCombo->currentIndex());
    m_optionCache.insert(ui.theoryCombo, ui.theoryCombo->currentIndex());
    m_optionCache.insert(ui.basisMolecCombo, ui.basisMolecCombo->currentIndex());
    //m_optionCache.insert(ui.stateCombo, ui.stateCombo->currentIndex()); // USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
    //m_optionCache.insert(ui.multiplicityCombo, // USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
    //                     ui.multiplicityCombo->currentIndex()); // USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
    //m_optionCache.insert(ui.chargeCombo, ui.chargeCombo->currentIndex()); // USEFUL FOR GAMESS BUT NOT FOR GAUSSIAN.
  }

  void SimuneAntInputDialog::restoreOptionCache()
  {
      qDebug()<<"I am in restoreOptionCache";
    foreach (QComboBox *combo, m_optionCache.keys()) {
      combo->blockSignals(true);
      combo->setCurrentIndex(m_optionCache.value(combo, 0));
      combo->blockSignals(false);
    }
  }

  void SimuneAntInputDialog::setBasicDefaults()
  {
      qDebug()<<"I am in setBasicDefaults";
    // Reset the form to defaults
    deckDirty(false);
    ui.titleLine->setText(QString());
    ui.calculationCombo->setCurrentIndex(0);
    ui.theoryCombo->setCurrentIndex(0);
    ui.basisMolecCombo->setCurrentIndex(0);
    ui.multiplicitySpin->setValue(0);
    ui.chargeSpin->setValue(0);
    ui.procSpin->setValue(2);

    QString alacant = qgetenv("ALACANT");
    ui.antgbrowseEdit->setText(alacant);
    QString g09root = qgetenv("g09root");
    ui.g09rootbrowseEdit->setText(g09root);
    ui.checkUseAntGBox->setChecked(true);
    ui.checkUseAntGl101->setChecked(true);
    ui.checkUseAntGl103->setChecked(true);
    ui.checkUseAntGl502->setChecked(true);
    ui.checkUseAntGl703->setChecked(false);

    ui.checkscfnosymm->setChecked(true);
    ui.checkscfnodamp->setChecked(true);
    ui.checkscfnovaracc->setChecked(true);

    ui.checkOpt->setChecked(false);
    ui.checkForce->setChecked(false);
  }

  void SimuneAntInputDialog::setIniDefaults()
  {
      qDebug()<<"I am in setIniDefaults";
    // Reset the form to defaults
    deckIniDirty(false);

    QSettings settings;

    ui.hamiltonCheck->setChecked(settings.value("ANT.G/Hamilton", true).toBool());
    ui.mullikenCheck->setChecked(settings.value("ANT.G/Mulliken", true).toBool());
    ui.alphaSpin->setValue(0.02);
    ui.paccSpin->setValue(8);
    ui.chargeaccSpin->setValue(6);
    ui.fermiaccSpin->setValue(6);
    ui.selfaccSpin->setValue(6);
    ui.biasvoltSpin->setValue(0.0);
    ui.qexcessSpin->setValue(0.0);
    ui.etaSpin->setValue(6);
    //ui.etaSpin->setValue(3);
    //ui.ssmSpin->setValue(4);
    ui.fermistartSpin->setValue(-5.0);
    ui.swoffsplSpin->setValue(3);

    ui.type1Combo->setCurrentIndex(0);
    ui.type2Combo->setCurrentIndex(0);

    ui.blpar1Combo->setCurrentIndex(0);
    ui.blpar2Combo->setCurrentIndex(0);

    ui.overlapSpin->setValue(0.0);

    ui.nembed1Spin->setValue(0);
    ui.nembed2Spin->setValue(0);

    ui.natomel1Spin->setValue(0);
    ui.natomel2Spin->setValue(0);

    ui.nalphaSpin->setValue(0);
    ui.nbetaSpin->setValue(0);

    ui.htransmCheck->setChecked(settings.value("ANT.G/Htransm", false).toBool());

    ui.estepSpin->setValue(2);

    ui.ew1Spin->setValue(-2.0);
    ui.ew2Spin->setValue(2.0);

    //ui.ldosbegSpin->setValue(0);
    //ui.ldosendSpin->setValue(0);

    ui.nchannelsSpin->setValue(0);

    ui.leaddosCheck->setChecked(settings.value("ANT.G/Leaddos", true).toBool());

    //ui.rtmbegSpin->setValue(0);
    //ui.rtmendSpin->setValue(0);
    ui.previewiniText->setText(generateInputIniDeck());
  }

  QString SimuneAntInputDialog::generateJobTitle() const
  {
      qDebug()<<"I am in generateJobTitle";
    QString calculation(ui.calculationCombo->currentText());
    QString theory(ui.theoryCombo->currentText());
    QString basis(ui.basisMolecCombo->currentText());
    QString formula(m_molecule ? QString::fromStdString(m_molecule->formula())
                               : tr("[no molecule]"));

    // Merge theory/basis into theory
    //theory += "/" + basis;
    theory += "-" + basis;
    theory.replace(QRegExp("\\s+"), "");

    //return QString("%1 | %2 | %3").arg(formula, calculation, theory);
    //return QString("%1-%2-%3").arg(formula, calculation, theory);
    return QString("%1-%2").arg(formula, theory);
  }

  void SimuneAntInputDialog::resetClicked()
  {
    qDebug()<<"I am in resetClicked";
    // Reset the form to defaults
    deckDirty(false);
    setBasicDefaults();
    setIniDefaults();
    updatePreviewComText();
    updatePreviewIniText();
  }

  void SimuneAntInputDialog::defaultsClicked()
  {
      qDebug()<<"I am in defaultClicked";
    setBasicDefaults();
    setIniDefaults();
    updatePreviewComText();
    updatePreviewIniText();
  }

  void SimuneAntInputDialog::updateTitlePlaceholder()
  {
      qDebug()<<"I am in updateTitlePlaceholder";
    ui.titleLine->setPlaceholderText(generateJobTitle());
  }

  void SimuneAntInputDialog::updateTitle()
  {
      qDebug()<<"I am in updateTitle";
    ui.titleLine->setText(generateJobTitle());
  }
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//---------- END OF CODE FROM AVOGADRO2 ----------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

  /*
  void SimuneAntInputDialog::showEvent(QShowEvent *)
  {
    updatePreviewComText();

    if (pathToG03().isEmpty())
      ui.computeButton->hide();
    else
      ui.computeButton->show();
  }
  */

  QString SimuneAntInputDialog::pathToG03() const
  {
      qDebug()<<"I am in pathToG03";
    QString returnPath;
    QStringList pathList;

    QStringList environment = QProcess::systemEnvironment();
    // This is a pain
    // Each item in the list is a key-value pair
    // so we match PATH
    // and then we split out the value (the bit after the =)
    // and split the PATH by ':' characters
    foreach(const QString &key, environment) {
      if (key.startsWith(QLatin1String("PATH")))
        pathList = key.split('=').at(1).split(':');
    }

    // Add default G03 and G09 directories
    //pathList << "/usr/local/g03" << "/usr/local/g09";
    if (qEnvironmentVariableIsSet("g09root"))
        pathList << qgetenv("g09root") <<"/g09";
    if (qEnvironmentVariableIsSet("g03root"))
        pathList << qgetenv("g03root") <<"/g03";

    // I don't know how this works for Windows -- probably need a different method
    foreach(const QString &path, pathList) {
      QFileInfo g03(path + '/' + "g03");
      if (g03.exists() && g03.isExecutable())
        returnPath = g03.canonicalFilePath();
      QFileInfo g09(path + '/' + "g09");
      if (g09.exists() && g09.isExecutable())
        returnPath = g09.canonicalFilePath();
    }

    return returnPath;
  }

  QString SimuneAntInputDialog::pathToG09() const
  {
      qDebug()<<"I am in pathToG09()";
    QString returnPath;
    QStringList pathList;

    QStringList environment = QProcess::systemEnvironment();
    // This is a pain
    // Each item in the list is a key-value pair
    // so we match PATH
    // and then we split out the value (the bit after the =)
    // and split the PATH by ':' characters
    foreach(const QString &key, environment) {
      if (key.startsWith(QLatin1String("PATH")))
        pathList = key.split('=').at(1).split(':');
    }

    // Add default G03 and G09 directories
    //pathList << "/usr/local/g03" << "/usr/local/g09";
    if (qEnvironmentVariableIsSet("g09root"))
        pathList << qgetenv("g09root") <<"/g09";
    if (qEnvironmentVariableIsSet("g03root"))
        pathList << qgetenv("g03root") <<"/g03";

    // I don't know how this works for Windows -- probably need a different method
    foreach(const QString &path, pathList) {
      QFileInfo g03(path + '/' + "g03");
      if (g03.exists() && g03.isExecutable())
        returnPath = g03.canonicalFilePath();
      QFileInfo g09(path + '/' + "g09");
      if (g09.exists() && g09.isExecutable())
        returnPath = g09.canonicalFilePath();
    }

    return returnPath;
  }

  QString SimuneAntInputDialog::pathToGaussian() const
  {
      qDebug()<<"I am in pathToGaussian";
    QString returnPath;
    QStringList pathList;

    //qputenv("g09root","/usr/local/gaussian09/g09-d1-intel-copied-from-krypton");
    qputenv("g09root","/usr/local/gaussian09/g09-b1-pgi");
    qputenv("GAUSS_SCRDIR","/home/carlos/SCRATCH");
    //qputenv("ALACANT","/usr/local/ANT.G/ANT.G-2.4.2-g09-d1-intel");
    qputenv("ALACANT","/usr/local/ANT.G/ANT.G-2.4.0-b1-stable");

    QString gausspath;

    if (qEnvironmentVariableIsSet("g09root")){
      gausspath = qgetenv("g09root");
      QString gauss_scrdir = qgetenv("GAUSS_SCRDIR");
      QString alacant = qgetenv("ALACANT");
      //qDebug()<<gausspath;
      //qDebug()<<gauss_scrdir;
      //qDebug()<<alacant;
    }

    QStringList environment = QProcess::systemEnvironment();
    // This is a pain
    // Each item in the list is a key-value pair
    // so we match PATH
    // and then we split out the value (the bit after the =)
    // and split the PATH by ':' characters
    foreach(const QString &key, environment) {
      if (key.startsWith(QLatin1String("PATH")))
        pathList = key.split('=').at(1).split(':');
    }

    // Add default G03 and G09 directories
    //pathList << "/usr/local/g03" << "/usr/local/g09";
    /*
    if (qEnvironmentVariableIsSet("g09root")){
        pathList << qgetenv("g09root") <<"/g09";
    }else if (qEnvironmentVariableIsSet("g03root")){
        pathList << qgetenv("g03root") <<"/g03";
    }
    */

    // I don't know how this works for Windows -- probably need a different method
    //foreach(const QString &path, pathList) {
      if(qEnvironmentVariableIsSet("g09root")){
        QFileInfo gaussian(gausspath + '/' + "g09" + '/' + "g09");
        if (gaussian.exists() && gaussian.isExecutable())
            returnPath = gaussian.canonicalFilePath();
            qDebug()<<"returnPath ="<<returnPath;
      }else if(qEnvironmentVariableIsSet("g03root")){
        QFileInfo gaussian(gausspath + '/' + "g03" + '/' + "g03");
        if (gaussian.exists() && gaussian.isExecutable())
            returnPath = gaussian.canonicalFilePath();
      }
    //}


    return returnPath;
  }

  /*
  void SimuneAntInputDialog::setMolecule(QtGui::Molecule *molecule)
  {
    // Disconnect the old molecule first...
    if (m_molecule) {
      disconnect(m_molecule, 0, this, 0);
    }

    m_molecule = molecule;
    // Update the preview text whenever atoms are changed
    connect(m_molecule, SIGNAL(atomRemoved(Core::Atom *)),
            this, SLOT(updatePreviewText()));
    connect(m_molecule, SIGNAL(atomAdded(Core::Atom *)),
            this, SLOT(updatePreviewText()));
    connect(m_molecule, SIGNAL(atomUpdated(Core::Atom *)),
            this, SLOT(updatePreviewText()));
    // Add atom coordinates
    updatePreviewText();
  }
  */

  void SimuneAntInputDialog::updatePreviewText()
  {
      qDebug() << "I am in updatePreviewText!!!";
      if (!isVisible()) {
        m_updatePending = true;
        return;
      }

      m_updatePending = false;

    //if (!isVisible()) // ALREADY WRITTEN AT THE TOP OF THE FUNCTION.
    //  return; // ALREADY WRITTEN AT THE TOP OF THE FUNCTION.
    // Generate the input deck and display it
    //if (m_dirty && !m_warned) { // ui.previewcomText->document()->isModified TAKEN FROM GAMESSINPUTDIALOG.
    //if ((m_dirty && !m_warned) || (ui.previewcomText->document()->isModified())) {
    if (m_dirty && !m_warned) {
      m_warned = true;
      QMessageBox msgBox;

      msgBox.setWindowTitle(tr("Gaussian Input Deck Generator Warning"));
      msgBox.setText(tr("Would you like to update the preview text, losing all changes made in the Gaussian input deck preview pane?"));
      msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);

      switch (msgBox.exec()) {
        case QMessageBox::Yes:
          // yes was clicked
          deckDirty(false);
          ui.previewcomText->setText(generateInputDeck());
          qDebug()<<"After 'ui.previewcomText->setText(generateInputDeck());' in updatePreviewText with m_dirty.";
          m_warned = false;
          break;
        case QMessageBox::No:
          // no was clicked
          restoreOptionCache();
          m_warned = false;
          break;
        default:
          // should never be reached
          restoreOptionCache();
          break;
      }
    }
    else if (!m_dirty){
      ui.previewcomText->setText(generateInputDeck());
      qDebug()<<"After 'ui.previewcomText->setText(generateInputDeck());' in updatePreviewText with !m_dirty";
    }
    ui.previewcomText->document()->setModified(false);
    updateOptionCache();
  }

  void SimuneAntInputDialog::updatePreviewComText()
  {
      qDebug() << "I am in updatePreviewComText!!!";
      if (!isVisible()) {
        m_updatePending = true;
        return;
      }

      m_updatePending = false;

    //if (!isVisible()) // ALREADY WRITTEN AT THE TOP OF THE FUNCTION.
    //  return; // ALREADY WRITTEN AT THE TOP OF THE FUNCTION.
    // Generate the input deck and display it
    //if (m_dirty && !m_warned) { // ui.previewcomText->document()->isModified TAKEN FROM GAMESSINPUTDIALOG.
    //if ((m_dirty && !m_warned) || (ui.previewcomText->document()->isModified())) {
    if (m_dirty && !m_warned) {
      m_warned = true;
      QMessageBox msgBox;

      msgBox.setWindowTitle(tr("Gaussian Input Deck Generator Warning"));
      msgBox.setText(tr("Would you like to update the preview text, losing all changes made in the Gaussian input deck preview pane?"));
      msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);

      switch (msgBox.exec()) {
        case QMessageBox::Yes:
          // yes was clicked
          deckDirty(false);
          ui.previewcomText->setText(generateInputDeck());
          qDebug()<<"After 'ui.previewcomText->setText(generateInputDeck());' in updatePreviewText with m_dirty.";
          m_warned = false;
          break;
        case QMessageBox::No:
          // no was clicked
          restoreOptionCache();
          m_warned = false;
          break;
        default:
          // should never be reached
          restoreOptionCache();
          break;
      }
    }
    else if (!m_dirty){
      ui.previewcomText->setText(generateInputDeck());
      qDebug()<<"After 'ui.previewcomText->setText(generateInputDeck());' in updatePreviewText with !m_dirty";
    }
    ui.previewcomText->document()->setModified(false);
    updateOptionCache();
  }

  /*
  void SimuneAntInputDialog::updatePreviewComText()
    {
      if (!isVisible())
        return;
      // Generate the input deck and display it
      if (m_dirty && !m_warned) {
        m_warned = true;
        QMessageBox msgBox;

        msgBox.setWindowTitle(tr("ANT.G Input Deck Generator Warning"));
        msgBox.setText(tr("Would you like to update the preview text, losing all changes made in the ANT.G input deck preview pane?"));
        msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);

        switch (msgBox.exec()) {
          case QMessageBox::Yes:
            // yes was clicked
            deckDirty(false);
            ui.previewcomText->setText(generateInputDeck());
            m_warned = false;
            break;
          case QMessageBox::No:
            // no was clicked
            m_warned = false;
            break;
          default:
            // should never be reached
            break;
        }
      }
      else if (!m_dirty)
        ui.previewcomText->setText(generateInputDeck());
    }
    */

    void SimuneAntInputDialog::updatePreviewIniText()
    {
      qDebug() << "I am in updatePreviewIniText!!!";
      if (!isVisible()) {
        m_updatePending = true;
        return;
      }

      m_updatePending = false;
      //if (!isVisible())
      //  return;

      // Generate the input deck and display it
      if (m_dirty && !m_warned) {
        m_warned = true;
        QMessageBox msgBox;

        msgBox.setWindowTitle(tr("ANT.G Input Deck Generator Warning"));
        msgBox.setText(tr("Would you like to update the preview text, losing all changes made in the ANT.G input deck preview pane?"));
        msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);

        switch (msgBox.exec()) {
          case QMessageBox::Yes:
            // yes was clicked
            deckDirty(false);
            ui.previewiniText->setText(generateInputIniDeck());
            m_warned = false;
            break;
          case QMessageBox::No:
            // no was clicked
            m_warned = false;
            break;
          default:
            // should never be reached
            break;
        }
      }
      else if (!m_dirty)
        ui.previewiniText->setText(generateInputIniDeck());

      ui.previewiniText->document()->setModified(false);
      updateOptionCache();
    }

  /*
  void SimuneAntInputDialog::resetClicked()
  {
    // Reset the form to defaults
    deckDirty(false);
    ui.calculationCombo->setCurrentIndex(1);
    ui.theoryCombo->setCurrentIndex(3);
    ui.basisMolecCombo->setCurrentIndex(2);
    ui.multiplicitySpin->setValue(0);
    ui.chargeSpin->setValue(0);
    ui.procSpin->setValue(1);
  }
  */

  QString SimuneAntInputDialog::saveInputFile(QString inputDeck, QString fileType, QString ext)
  {
    qDebug()<<"I am in saveInputFile";
// Fragment copied from InputDialog
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME
    //QFileInfo defaultFile(m_molecule->fileName());
    //QFileInfo defaultFile(m_molecule->objectName());
    //QFileInfo defaultFile(m_outputFileName);
    QString defaultName(m_molecule->objectName());
    if(m_molecule->objectName().isEmpty()){
        QString defaultName(ui.titleLine->text());
        if (defaultName.isEmpty())
          defaultName = generateJobTitle();
        //m_title=title;
        //
    }

    QFileInfo defaultFile(defaultName);

    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("saveInputFile:Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    if(fileName == "")
      return fileName;

    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();
// end of copied

    // checkpoint
    QString checkpointName = QFileInfo(fileName).baseName();
    checkpointName.prepend("%Chk=");
    checkpointName.append(".chk");
    inputDeck.replace(QLatin1String("%Chk=checkpoint.chk"), checkpointName, Qt::CaseInsensitive);

// Fragment copied from InputDialog
    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();
    return fileName;
  }

  /*
  QString InputDialog::saveInputFile(QString inputDeck, QString fileType, QString ext)
  {
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME

    QFileInfo defaultFile(m_molecule->fileName()); // REPLACED BELOW TO WORK IN AVOGADRO2
    //QFileInfo defaultFile(m_outputFileName);

    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    if(fileName == "")
      return fileName;

    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();

    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();
    return fileName;
  }
  */

  /*
  void SimuneAntInputDialog::generateClicked() // CORRECTED BELOW TO WORK WITH AVOGADRO2 AND WITHOUT Inputdialog::saveInputFile()
  {
    saveInputFile(ui.previewcomText->toPlainText(),
                          tr("Gaussian Input Deck"), QString("com"));
  }
  */

  QString SimuneAntInputDialog::saveAntInputFiles(QString inputDeck, QString inputiniDeck, QString fileType, QString ext, QString iniext)
  {
    qDebug()<<"I am in saveAntInputFiles";
// Fragment copied from InputDialog
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME
    //QFileInfo defaultFile(m_molecule->fileName());
    QString defaultName(m_molecule->objectName());
    if(m_molecule->objectName().isEmpty()){
        QString defaultName(ui.titleLine->text());
        if (defaultName.isEmpty())
          defaultName = generateJobTitle();
        //m_title=title;
        //
    }

    QFileInfo defaultFile(defaultName);

    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("saveAntInputFiles:Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    //QString defaultiniFileName = defaultPath + '/' + defaultFile.baseName() + "." + iniext;
    //QString inifileName = QFileDialog::getSaveFileName(this, tr("saveAntInputFiles:Save Input Ini Deck"),
    //    defaultiniFileName, fileType + " (*." + iniext + ")");

    if(fileName == "")
      return fileName;

    ui.savecomLineEdit->setText(fileName);
    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();

    //QFile inifile(fileName);
    //if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();
    // .ini ANT.G
    QString inifileName = QFileInfo(fileName).baseName();
    QString logfileName = inifileName;
    QString inifilePath = QFileInfo(fileName).absolutePath();
    inputDeck.replace(QLatin1String("Title"), inifileName, Qt::CaseInsensitive);
    inifileName.append(".ini");
    logfileName.append(".log");
    ui.saveiniLineEdit->setText(inifilePath + "/" + inifileName);
    ui.savelogLineEdit->setText(inifilePath + "/" + logfileName);
    QFile inifile(inifileName);
    if(!inifile.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();
// end of copied

    // checkpoint
    QString checkpointName = QFileInfo(fileName).baseName();
    checkpointName.prepend("%Chk=");
    checkpointName.append(".chk");
    inputDeck.replace(QLatin1String("%Chk=checkpoint.chk"), checkpointName, Qt::CaseInsensitive);

// Fragment copied from InputDialog
    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();

    // .ini ANT.G
    inifile.write(inputiniDeck.toLocal8Bit()); // prevent troubles in Windows
    inifile.close(); // flush buffer!
    m_savePath = QFileInfo(inifile).absolutePath(); // Don't write this. Would lead to an error.

    saveAntIniFile(ui.previewiniText ->toPlainText(),
                          tr("ANT.G .ini Input Deck"), QString("ini"));

    return fileName;
  }

  QString SimuneAntInputDialog::saveAntComFile(QString inputDeck, QString fileType, QString ext)
  {
// Fragment copied from InputDialog
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME
    //QFileInfo defaultFile(m_molecule->fileName());
    QString defaultName(m_molecule->objectName());
    if(m_molecule->objectName().isEmpty()){
        QString defaultName(ui.titleLine->text());
        if (defaultName.isEmpty())
          defaultName = generateJobTitle();
        //m_title=title;
        //
    }

    QFileInfo defaultFile(defaultName);

    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("saveAntComFile: Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    if(fileName == "")
      return fileName;

    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();
// end of copied

    // checkpoint
    QString checkpointName = QFileInfo(fileName).baseName();
    checkpointName.prepend("%Chk=");
    checkpointName.append(".chk");
    inputDeck.replace(QLatin1String("%Chk=checkpoint.chk"), checkpointName, Qt::CaseInsensitive);

// Fragment copied from InputDialog
    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();
    return fileName;
  }

  QString SimuneAntInputDialog::saveAntIniFile(QString inputDeck, QString fileType, QString ext)
  {
// Fragment copied from InputDialog
    // Try to set default save path for dialog using the next sequence:
    //  1) directory of current file (if any);
    //  2) directory where previous deck was saved;
    //  3) $HOME
    //QFileInfo defaultFile(m_molecule->fileName());
    QString defaultName(m_molecule->objectName());
    if(m_molecule->objectName().isEmpty()){
        QString defaultName(ui.titleLine->text());
        if (defaultName.isEmpty())
          defaultName = generateJobTitle();
        //m_title=title;
        //
    }

    QFileInfo defaultFile(defaultName);
    QString defaultPath = defaultFile.canonicalPath();
    if(m_savePath == "") {
      if (defaultPath.isEmpty())
        defaultPath = QDir::homePath();
    } else {
      defaultPath = m_savePath;
    }

    QString defaultFileName = defaultPath + '/' + defaultFile.baseName() + "." + ext;
    QString fileName = QFileDialog::getSaveFileName(this, tr("saveAntIniFile: Save Input Deck"),
        defaultFileName, fileType + " (*." + ext + ")");

    if(fileName == "")
      return fileName;

    QFile file(fileName);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Text)) return QString();
// end of copied

    // checkpoint
    QString checkpointName = QFileInfo(fileName).baseName();
    checkpointName.prepend("%Chk=");
    checkpointName.append(".chk");
    inputDeck.replace(QLatin1String("%Chk=checkpoint.chk"), checkpointName, Qt::CaseInsensitive);

// Fragment copied from InputDialog
    file.write(inputDeck.toLocal8Bit()); // prevent troubles in Windows
    file.close(); // flush buffer!
    m_savePath = QFileInfo(file).absolutePath();
    return fileName;
  }

  void SimuneAntInputDialog::generateClicked()
  {
      qDebug()<<"I am in generateClicked";
    QSettings settings;


    QString fileName = (ui.baseNameEdit->text().isEmpty()
                        ? ui.baseNameEdit->placeholderText()
                        : ui.baseNameEdit->text()) + ".com";
    QString targetFile = settings.value("gaussianInput/outputDirectory",
                                       QDir::homePath()).toString();

    /*
    QString fileName = (ui.titleLine->text().isEmpty()
                        ? ui.titleLine->placeholderText()
                        : ui.titleLine->text()) + ".com";
    QString targetFile = settings.value("gaussianInput/outputDirectory",
                                       QDir::homePath()).toString();
    */
    targetFile = QDir(QFileInfo(targetFile).absoluteDir()).absoluteFilePath(
          fileName);

    fileName = QFileDialog::getSaveFileName(this, tr("Save GAUSSIAN input file"),
                                            targetFile);

    // User cancel:
    if (fileName.isNull())
      return;

    settings.setValue("gaussianInput/outputDirectory", fileName);

    QFile file(fileName);
    bool success = false;
    if (file.open(QFile::WriteOnly | QFile::Text)) {
      if (file.write(ui.previewcomText->toPlainText().toLatin1()) > 0) {
        success = true;
      }
      file.close();
    }

    if (!success) {
      QMessageBox::critical(this, tr("Output Error"),
                            tr("Failed to write to file %1.").arg(fileName));
    }
  }

  void SimuneAntInputDialog::saveAntComClicked()
  {
    saveAntComFile(ui.previewcomText ->toPlainText(),
                          tr("ANT.G .com Input Deck"), QString("com"));
  }

  void SimuneAntInputDialog::saveAntIniClicked()
  {
    saveAntIniFile(ui.previewiniText ->toPlainText(),
                          tr("ANT.G .ini Input Deck"), QString("ini"));
  }

  /*
  void SimuneAntInputDialog::submitClicked()
  {
      qDebug()<<"I am in submitClicked";
    // Verify that molequeue is running:
    MoleQueueManager &mqManager = MoleQueueManager::instance();
    if (!mqManager.connectIfNeeded()) {
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }

    QString description(ui.titleLine->text());
    if (description.isEmpty())
      description = generateJobTitle();

    QString fileNameBase = ui.baseNameEdit->text().isEmpty()
        ? ui.baseNameEdit->placeholderText() : ui.baseNameEdit->text();

    JobObject job;
    job.setProgram("SIMUNE ANT.G");
    job.setDescription(description);
    job.setInputFile(QString("%1.com").arg(fileNameBase),
                     ui.previewcomText->toPlainText());

    job.appendAdditionalInputFile(QString("%1.ini").arg(fileNameBase), // ADDED BY C.SALGADO
                                  ui.previewiniText->toPlainText()); // ADDED BY C.SALGADO

    MoleQueueDialog::SubmitStatus submitStatus =
        MoleQueueDialog::submitJob(this,
                                   tr("Submit SIMUNE ANT.G Calculation"),
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
  */

  void SimuneAntInputDialog::submitClicked()
  {
    qDebug()<<"I am in submitClicked";
    // Verify that molequeue is running:
    MoleQueueManager &mqManager = MoleQueueManager::instance();
    if (!mqManager.connectIfNeeded()) {
      qDebug()<<"mqManager.connectIfNeeded() is FALSE";
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }else{
      qDebug()<<"mqManager.connectIfNeeded() is TRUE";
    }

    QString description(ui.titleLine->text());
    qDebug()<<"ui.titleLine->text()"<<ui.titleLine->text();
    if (description.isEmpty())
      description = generateJobTitle();

    qDebug()<<"ui.baseNameEdit>text()"<<ui.baseNameEdit->text();
    qDebug()<<"ui.baseNameEdit>placeholderText()"<<ui.baseNameEdit->placeholderText();
    QString fileNameBase = ui.baseNameEdit->text().isEmpty()
        ? ui.baseNameEdit->placeholderText() : ui.baseNameEdit->text();
    //QString fileNameBase = ui.titleLine->text();
    qDebug()<<"fileNameBase = "<<fileNameBase;

    JobObject job;
    job.setProgram("SIMUNE ANT.G");
    job.setDescription(description);
    qDebug()<<"ui.previewText->toPlainText()"<<ui.previewcomText->toPlainText();
    job.setInputFile(QString("%1.com").arg(fileNameBase),
                     ui.previewcomText->toPlainText());
    job.appendAdditionalInputFile(QString("%1.ini").arg(fileNameBase), // ADDED BY C.SALGADO
                     ui.previewiniText->toPlainText()); // ADDED BY C.SALGADO


    qDebug()<<"After job.setInputFile";

    //qSleep(1000);
    //QTest::qWait(2000);
    qDebug()<<"After waiting qSleep(1000);";
    MoleQueueDialog::SubmitStatus submitStatus =
        MoleQueueDialog::submitJob(this,
                                   tr("Submit SIMUNE ANT.G Calculation"),
                                   job, MoleQueueDialog::WaitForSubmissionResponse
                                   | MoleQueueDialog::SelectProgramFromTemplate);

    switch (submitStatus) {
    default:
    case MoleQueueDialog::SubmissionSuccessful:
      qDebug()<<"MoleQueueDialog::SubmissionSuccessful";
    case MoleQueueDialog::SubmissionFailed:
      qDebug()<<"MoleQueueDialog::SubmissionFailed";
    case MoleQueueDialog::SubmissionAttempted:
      qDebug()<<"MoleQueueDialog::SubmissionAttempted";
    case MoleQueueDialog::SubmissionAborted:
      qDebug()<<"MoleQueueDialog::SubmissionAborted";
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

/*
  void SimuneAntInputDialog::computeClicked()
  {
    qDebug()<<"I am in computeClicked";
    //if (m_process != 0) {
    //  QMessageBox::warning(this, tr("Gaussian Running."),
    //                       tr("Gaussian is already running. Wait until the previous calculation is finished."));
    //  return;
    //}

    //QString fileName = saveInputFile(ui.previewcomText->toPlainText(),
    //                      tr("Gaussian Input Deck"), QString("com"));
    QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                          tr("ANT.G Input Deck"), QString("com"), QString("ini"));
    if (fileName.isEmpty())
      return;


    //if(qEnvironmentVariableIsSet("g09root")){
    //    QFileInfo info(pathToG09());
    //}else if(qEnvironmentVariableIsSet("g03root")){
    //    QFileInfo info(pathToG03());
    //}

    QFileInfo info(pathToGaussian());

    if (!info.exists() || !info.isExecutable()) {
      QMessageBox::warning(this, tr("Gaussian Not Installed."),
                           tr("The Gaussian executable, cannot be found."));
      return;
    }

    QString avogadrobuildpath = qgetenv("PWD");

    m_process = new QProcess(this);
    QFileInfo input(fileName);
    m_process->setWorkingDirectory(input.absolutePath());

    QStringList arguments;
    arguments << fileName;
    //arguments << pathToGaussian() << fileName << output;
    m_inputFile = fileName; // save for reading in output

    //m_process->start(pathToGaussian(), arguments);
    QString program = avogadrobuildpath + "/g09ANT.Gscript.sh";
    qDebug() << "PROGRAM = " + program;
    //QString program = pathToGaussian();
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->start(program,arguments);

    if (!m_process->waitForStarted()) {
      QMessageBox::warning(this, tr("Gaussian failed to start."),
                           tr("Gaussian did not start. Perhaps it is not installed correctly."));
    }
    connect(m_process, SIGNAL(finished(int)), this, SLOT(finished(int)));
    m_progress = new QProgressDialog(this);
    m_progress->setRange(0,0); // indeterminate progress
    m_progress->setLabelText(tr("Running SIMUNE ANT.G calculation..."));
    m_progress->show();
    connect(m_progress, SIGNAL(canceled()), this, SLOT(stopProcess()));
  }
  */

  void SimuneAntInputDialog::computeClicked()
  {
    qDebug()<<"I am in computeClicked";
    /*if (m_process != 0) {
      QMessageBox::warning(this, tr("Gaussian Running."),
                           tr("Gaussian is already running. Wait until the previous calculation is finished."));
      return;
    }*/

    //QString fileName = saveInputFile(ui.previewText->toPlainText(),
    //                      tr("Gaussian Input Deck"), QString("com"));
    QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                          tr("ANT.G Input Deck"), QString("com"), QString("ini"));
    if (fileName.isEmpty())
      return;

    /*
    if(qEnvironmentVariableIsSet("g09root")){
        QFileInfo info(pathToG09());
    }else if(qEnvironmentVariableIsSet("g03root")){
        QFileInfo info(pathToG03());
    }
    */
    QFileInfo info(pathToGaussian());

    if (!info.exists() || !info.isExecutable()) {
      QMessageBox::warning(this, tr("Gaussian Not Installed."),
                           tr("The Gaussian executable, cannot be found."));
      return;
    }

    QString avogadrobuildpath = qgetenv("PWD");

    m_process = new QProcess(this);
    QFileInfo input(fileName);
    m_process->setWorkingDirectory(input.absolutePath());

    QStringList arguments;
    arguments << fileName;
    //arguments << pathToGaussian() << fileName << output;
    m_inputFile = fileName; // save for reading in output

    //m_process->start(pathToGaussian(), arguments);
    QString program = avogadrobuildpath + "/g09ANT.Gscript.sh";
    qDebug() << "PROGRAM = " + program;
    //QString program = pathToGaussian();
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->start(program,arguments);

    m_process->waitForStarted(10000);
    if (!m_process->waitForStarted()) {
      QMessageBox::warning(this, tr("Gaussian failed to start."),
                           tr("Gaussian did not start. Perhaps it is not installed correctly."));
    }
    connect(m_process, SIGNAL(finished(int)), this, SLOT(finished(int)));
    m_progress = new QProgressDialog(this);
    m_progress->setRange(0,0); // indeterminate progress
    m_progress->setLabelText(tr("Running Gaussian calculation..."));
    m_progress->show();
    connect(m_progress, SIGNAL(canceled()), this, SLOT(stopProcess()));
  }

  /*
  void SimuneAntInputDialog::computeClicked()
  {
    qDebug()<<"I am in computeClicked";
    //if (m_process != 0) {
    //  QMessageBox::warning(this, tr("Gaussian Running."),
    //                       tr("Gaussian is already running. Wait until the previous calculation is finished."));
    //  return;
    //}

    //QString fileName = saveInputFile(ui.previewText->toPlainText(),
    //                      tr("Gaussian Input Deck"), QString("com"));
    QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                          tr("ANT.G Input Deck"), QString("com"), QString("ini"));
    if (fileName.isEmpty())
      return;


    //if(qEnvironmentVariableIsSet("g09root")){
    //    QFileInfo info(pathToG09());
    //}else if(qEnvironmentVariableIsSet("g03root")){
    //    QFileInfo info(pathToG03());
    //}

    QFileInfo info(pathToGaussian());

    if (!info.exists() || !info.isExecutable()) {
      QMessageBox::warning(this, tr("Gaussian Not Installed."),
                           tr("The Gaussian executable, cannot be found."));
      return;
    }

    QString avogadrobuildpath = qgetenv("PWD");

    m_process = new QProcess(this);
    QFileInfo input(fileName);
    m_process->setWorkingDirectory(input.absolutePath());

    QStringList arguments;
    arguments << fileName;
    //arguments << pathToGaussian() << fileName << output;
    m_inputFile = fileName; // save for reading in output

    //m_process->start(pathToGaussian(), arguments);
    QString program = avogadrobuildpath + "/g09ANT.Gscript.sh";
    qDebug() << "PROGRAM = " + program;
    //QString program = pathToGaussian();
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->start(program,arguments);

    if (!m_process->waitForStarted()) {
      QMessageBox::warning(this, tr("Gaussian failed to start."),
                           tr("Gaussian did not start. Perhaps it is not installed correctly."));
    }
    connect(m_process, SIGNAL(finished(int)), this, SLOT(finished(int)));
    m_progress = new QProgressDialog(this);
    m_progress->setRange(0,0); // indeterminate progress
    m_progress->setLabelText(tr("Running Gaussian calculation..."));
    m_progress->show();
    connect(m_progress, SIGNAL(canceled()), this, SLOT(stopProcess()));
  }
  */

  /*
  void SimuneAntInputDialog::computeClickedAnt()
  {
      qDebug()<<"I am in computeClickedAnt";
    //if (m_process != 0) {
    //  QMessageBox::warning(this, tr("ANT.G Running."),
    //                       tr("ANT.G is already running. Wait until the previous calculation is finished."));
    //  return;
    }

    //QString fileName = saveInputFile(ui.previewcomText->toPlainText(),
    //                      tr("ANT.G Input Deck"), QString("com"));
    QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                          tr("ANT.G Input Deck"), QString("com"), QString("ini"));
    //QString fileName = saveInputFile(ui.previewcomText->toPlainText(),
    //QFileDialog                      tr("Gaussian Input Deck"), QString("com"));
    if (fileName.isEmpty())
      return;

    QFileInfo info(pathToGaussian());
    if (!info.exists() || !info.isExecutable()) {
      QMessageBox::warning(this, tr("Gaussian Not Installed."),
                           tr("The Gaussian executable, cannot be found."));
      return;
    }

    QString avogadrobuildpath = qgetenv("PWD");

    m_process = new QProcess(this);
    QFileInfo input(fileName);
    m_process->setWorkingDirectory(input.absolutePath());

    //-------------------------------------------------------------------------
    QString output = ui.savelogLineEdit->text();
    //QString output = ui.baseNameEdit->text();
    if(output.isEmpty()) {
        qDebug() << "No output";
        QMessageBox::information(this,
                     tr("launchgaussian"),tr("Output file not specified"));
        return;
    }

    connect(m_process, SIGNAL(started()), this, SLOT(processStarted()));
    //connect(m_process,SIGNAL(readyReadStandardOutput()),this,SLOT(readyReadStandardOutput()));
    //qDebug() << "after  readyReadStandardOutput" << SLOT(readyReadStandardOutput());
    //connect(m_process, SIGNAL(finished(int)), this, SLOT(runningFinished()));
    //-------------------------------------------------------------------------


    //QStringList arguments;
    ////arguments << fileName;
    ////arguments << fileName + " | tee " + output;
    //arguments << pathToGaussian() << fileName << output;
    //qDebug() << arguments;
    //m_inputFile = fileName; // save for reading in output

    QStringList arguments;
    arguments << fileName;
    //arguments << pathToGaussian() << fileName << output;
    m_inputFile = fileName; // save for reading in output

    //m_process->start(pathToGaussian(), arguments);
    QString program = avogadrobuildpath + "/g09ANT.Gscript.sh";
    qDebug() << "PROGRAM = " + program;
    //QString program = pathToGaussian();
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->start(program,arguments);

    //if (!m_process->waitForStarted()) {
    if (!m_process->waitForStarted()) {
      QMessageBox::warning(this, tr("ANT.G failed to start."),
                           tr("ANT.G did not start. Perhaps it is not installed correctly."));
    }
    //-----------------------------------------------------------------------
    //connect(m_process, SIGNAL(started()), this, SLOT(processStarted()));
    connect(m_process,SIGNAL(readyReadStandardOutput()),this,SLOT(read_m_process_StandardOutput()));
    //qDebug() << "after  readyReadStandardOutput" << SLOT(readyReadStandardOutput());
    //-----------------------------------------------------------------------

    connect(m_process, SIGNAL(finished(int)), this, SLOT(finished(int)));
    m_progress = new QProgressDialog(this);
    m_progress->setRange(0,0); // indeterminate progress
    m_progress->setLabelText(tr("Running SIMUNE ANT.G calculation..."));
    m_progress->show();
    connect(m_progress, SIGNAL(canceled()), this, SLOT(stopProcess()));
  }
  */

  void SimuneAntInputDialog::computeClickedAnt()
  {
      qDebug()<<"I am in computeClickedAnt";
    /*if (m_process != 0) {
      QMessageBox::warning(this, tr("ANT.G Running."),
                           tr("ANT.G is already running. Wait until the previous calculation is finished."));
      return;
    }*/

    //QString fileName = saveInputFile(ui.previewcomText->toPlainText(),
    //                      tr("ANT.G Input Deck"), QString("com"));
    QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                          tr("ANT.G Input Deck"), QString("com"), QString("ini"));
    //QString fileName = saveInputFile(ui.previewText->toPlainText(),
    //QFileDialog                      tr("Gaussian Input Deck"), QString("com"));
    if (fileName.isEmpty())
      return;

    QFileInfo info(pathToGaussian());
    if (!info.exists() || !info.isExecutable()) {
      QMessageBox::warning(this, tr("Gaussian Not Installed."),
                           tr("The Gaussian executable, cannot be found."));
      return;
    }

    m_process = new QProcess(this);
    QFileInfo input(fileName);
    m_process->setWorkingDirectory(input.absolutePath());

    //-------------------------------------------------------------------------
    QString output = ui.savelogLineEdit->text();
    //QString output = ui.baseNameEdit->text();
    if(output.isEmpty()) {
        qDebug() << "No output";
        QMessageBox::information(this,
                     tr("launchgaussian"),tr("Output file not specified"));
        return;
    }

    connect(m_process, SIGNAL(started()), this, SLOT(processStarted()));
    //connect(m_process,SIGNAL(readyReadStandardOutput()),this,SLOT(readyReadStandardOutput()));
    //qDebug() << "after  readyReadStandardOutput" << SLOT(readyReadStandardOutput());
    //connect(m_process, SIGNAL(finished(int)), this, SLOT(runningFinished()));
    //-------------------------------------------------------------------------

    QStringList arguments;
    //arguments << fileName;
    //arguments << fileName + " | tee " + output;
    arguments << pathToGaussian() << fileName << output;
    qDebug() << arguments;

    m_inputFile = fileName; // save for reading in output

    QString avogadrobuildpath = qgetenv("PWD");
    //m_process->start(pathToGaussian(), arguments);
    QString program = avogadrobuildpath + "/g09ANT.Gscript.sh";
    qDebug() << 'PROGRAM = ' + program;
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    m_process->start(program,arguments);
    //if (!m_process->waitForStarted()) {
    if (!m_process->waitForStarted()) {
      QMessageBox::warning(this, tr("G09 failed to start."),
                           tr("G09 did not start. Perhaps it is not installed correctly."));
    }
    //-----------------------------------------------------------------------
    //connect(m_process, SIGNAL(started()), this, SLOT(processStarted()));
    connect(m_process,SIGNAL(readyReadStandardOutput()),this,SLOT(read_m_process_StandardOutput()));
    //qDebug() << "after  readyReadStandardOutput" << SLOT(readyReadStandardOutput());
    //-----------------------------------------------------------------------

    connect(m_process, SIGNAL(finished(int)), this, SLOT(finished(int)));
    m_progress = new QProgressDialog(this);
    m_progress->setRange(0,0); // indeterminate progress
    m_progress->setLabelText(tr("Running Gaussian calculation..."));
    m_progress->show();
    connect(m_progress, SIGNAL(canceled()), this, SLOT(stopProcess()));
  }

  void SimuneAntInputDialog::stopProcess()
  {
      qDebug()<<"I am in stopProcess";
    if (m_progress) {
      m_progress->deleteLater();
      m_progress = 0;
    }

    disconnect(m_process, 0, this, 0); // don't send a "finished" signal
    m_process->close();
    m_process->deleteLater();
    m_process = 0;
  }

  void SimuneAntInputDialog::finished(int exitCode)
  {
      qDebug()<<"I am in finished";
    if (m_progress) {
      m_progress->cancel();
      m_progress->deleteLater();
      m_progress = 0;
    }

    if (m_process) {
      disconnect(m_process, 0, this, 0);
      m_process->deleteLater();
      m_process = 0;
    } else {
      return; // we probably cancelled
    }

    if (exitCode) {
      QMessageBox::warning(this, tr("SIMUNE ANT.G Crashed."),
                           tr("SIMUNE ANT.G did not run correctly. Perhaps it is not installed correctly."));
     return;
    }

    if (!m_molecule)
      return;

    // we have a successful run.
    // try to run formchk
    QFileInfo inputFile(m_inputFile);
    QString checkpointFileName = inputFile.canonicalPath() + '/' + inputFile.baseName() + ".chk";
    QFileInfo checkpointFile(checkpointFileName);
    if (checkpointFile.exists() && checkpointFile.isReadable()) {
      // let's see if formchk exists
      QString formchkFilePath = QFileInfo(pathToG03()).canonicalPath() + '/' + "formchk";
      QFileInfo formchkInfo(formchkFilePath);
      if (formchkInfo.exists() && formchkInfo.isExecutable()) {
        QStringList arguments;
        arguments << checkpointFileName;
        QProcess::execute(formchkFilePath, arguments); // if this fails, it's not a big deal
      }
    }
    
    // Now, read in the results and close the dialog
    QString outputFile = inputFile.canonicalPath() + '/' + inputFile.baseName() + ".log";
    emit readOutput(outputFile);

    //close();
  }

  void SimuneAntInputDialog::moreClicked()
  {
      qDebug()<<"I am in moreClicked";
    // If the more button is clicked hide/show the preview text
    if (ui.previewcomText->isVisible()) {
      ui.previewcomText->hide();
      ui.moreButton->setText(tr("Show Preview"));
    }
    else {
      ui.previewcomText->show();
      ui.moreButton->setText(tr("Hide Preview"));
    }
  }

  void SimuneAntInputDialog::enableFormClicked()
  {
      qDebug()<<"I am in enableFormClicked";
    deckDirty(false);
    updatePreviewComText();
    updatePreviewIniText();
  }

  void SimuneAntInputDialog::previewEdited()
  {
    qDebug()<<"I am in previewEdited";
    // Determine if the preview text has changed from the form generated
    if(ui.previewcomText->toPlainText() != generateInputDeck())
      deckDirty(true);
    else
      deckDirty(false);
  }

  void SimuneAntInputDialog::previewIniEdited()
  {
    // Determine if the preview text has changed from the form generated
    if(ui.previewiniText->toPlainText() != generateInputIniDeck())
      deckIniDirty(true);
    else
      deckIniDirty(false);
  }

  void SimuneAntInputDialog::getTitle()
  {
    m_title = ui.titleLine->text();
    ui.baseNameEdit->setText(m_title);
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setCalculation(int n)
  {
    switch (n)
    {
      case 0:
        m_calculationType = SP;
        break;
      case 1:
        m_calculationType = OPT;
        break;
      case 2:
        m_calculationType = FREQ;
        break;
      default:
        m_calculationType = SP;
    }
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setTheory(int n)
  {
    switch (n)
    {
      case 0:
        m_theoryType = lsda;
        break;
      case 1:
        m_theoryType = bpbe;
        break;
      case 2:
        m_theoryType = blyp;
        break;
      case 3:
        m_theoryType = B3LYP;
        break;
      case 4:
        m_theoryType = hseh1pbe;
        break;
      default:
        m_theoryType = lsda;
    }

    //if (m_theoryType == AM1 || m_theoryType == PM3)
    //  ui.basisMolecCombo->setEnabled(false);
    //else
      ui.basisMolecCombo->setEnabled(true);

    updatePreviewComText();
  }


  void SimuneAntInputDialog::setBasis(int n)
  {
    switch (n)
    {
      case 0:
        m_basisType = CRENBS;
        break;
      case 1:
        m_basisType = minimal6s;
        break;
      case 2:
        m_basisType = LANL2DZ;
        break;
      case 3:
        m_basisType = STO3G;
        break;
      case 4:
        m_basisType = B321G;
        break;
      case 5:
        m_basisType = B631Gd;
        break;
      case 6:
        m_basisType = B631Gdp;
        break;
      default:
        m_basisType = CRENBS;
    }
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setMolecBasis(int n)
  {
      qDebug()<<"I am in setMolecBasis(int n)";
    switch (n)
    {
      case 0:
        m_basisType = STO3G;
        break;
      case 1:
        m_basisType = B321G;
        break;
      case 2:
        m_basisType = B631Gd;
        break;
      case 3:
        m_basisType = B631Gdp;
        break;
      case 4:
        m_basisType = LANL2DZ;
        break;
      default:
        m_basisType = B631Gd;
    }
    qDebug()<<"Entering getLoadFullBasisType";

    //getLoadFullBasisType(n);

    qDebug()<<"Entering updatePreviewComText";

    updatePreviewComText();
  }

  void SimuneAntInputDialog::setMultiplicity(int n)
  {
      qDebug()<<"I am in setMultiplicity";
    m_multiplicity = n;
    updatePreviewComText();
  }
  void SimuneAntInputDialog::setCharge(int n)
  {
      qDebug()<<"I am in setCharge";
    m_charge = n;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setProcs(int n)
  {
      qDebug()<<"I am in setProcs";
    if (n > 0)
      m_procs = n;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setOutput(int n)
  {
      qDebug()<<"I am in setOutput";
    switch (n)
    {
      case 1:
        m_output = " gfprint pop=full";
        break;
      case 2:
        m_output = " gfoldprint pop=full";
        break;
      default:
        m_output = "";
    }
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setChk(int n)
  {
      qDebug()<<"I am in setChk";
    if (n) m_chk = true;
    else m_chk = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUseAntG(int n)
  {
      qDebug()<<"I am in setUseAntG";
    if (n) m_useAntG = true;
    else m_useAntG = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUseAntGl101(int n)
  {
      qDebug()<<"I am in setUseAntGl101";
    if (n) m_l101 = true;
    else m_l101 = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUseAntGl103(int n)
  {
      qDebug()<<"I am in setUseAntGl103";
    if (n) m_l103 = true;
    else m_l103 = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUseAntGl502(int n)
  {
      qDebug()<<"I am in setUseAntGl502";
    if (n) m_l502 = true;
    else m_l502 = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUseAntGl703(int n)
  {
      qDebug()<<"I am in setUseAntGl703";
    if (n) m_l703 = true;
    else m_l703 = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setCoords(int n)
  {
      qDebug()<<"I am in setCoords";
    switch (n)
    {
      case 0:
        m_coordType = CARTESIAN;
        break;
      case 1:
        m_coordType = ZMATRIX;
        break;
      case 2:
        m_coordType = ZMATRIX_COMPACT;
        break;
      default:
        m_coordType = CARTESIAN;
    }
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setUHF(int n)
  {
      qDebug()<<"I am in setUHF";
    if (n) m_UHF = true;
    else m_UHF = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setglobalnosymm(int n)
  {
      qDebug()<<"I am in setglobalnosymm";
    if (n) m_globalnosymm = true;
    else m_globalnosymm = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setscfConver(int n)
  {
      qDebug()<<"I am in setscfConver";
    m_scfConver = n;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setscfMaxCycle(int n)
  {
      qDebug()<<"I am in setscfMaxCycle";
    m_scfMaxCycle = n;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setscfnosymm(int n)
  {
      qDebug()<<"I am in setscfnosymm";
    if (n) m_scfnosymm = true;
    else m_scfnosymm = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setscfnodamp(int n)
  {
      qDebug()<<"I am in setscfnodamp";
    if (n) m_scfnodamp = true;
    else m_scfnodamp = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setscfnovaracc(int n)
  {
      qDebug()<<"I am in setscfnovaracc";
    if (n) m_scfnovaracc = true;
    else m_scfnovaracc = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setoptmaxcycles(int n)
  {
      qDebug()<<"I am in sescfConver";
    m_optmaxcycles = n;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setoptAccuracy(int n)
  {
      qDebug()<<"I am in setoptAccuracy(int n)";
    switch (n)
    {
      case 0:
        m_optAccuracy = loose;
        break;
      case 1:
        m_optAccuracy = tight;
        break;
      case 2:
        m_optAccuracy = verytight;
        break;
      default:
        m_optAccuracy = loose;
    }
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setOpt(int n)
  {
      qDebug()<<"I am in setOpt";
    if (n) m_opt = true;
    else m_opt = false;
    updatePreviewComText();
  }

  void SimuneAntInputDialog::setForce(int n)
  {
      qDebug()<<"I am in setForce";
    if (n) m_force = true;
    else m_force = false;
    updatePreviewComText();
  }

















  QString SimuneAntInputDialog::generateInputDeck()
  {
    qDebug() << "I am in generateInputdeck!!!";
    // Generate an input deck based on the settings of the dialog
    QString buffer;
    QTextStream mol(&buffer);

    // These directives are required before the job specification
    if (m_procs > 1)
      mol << "%NProcShared=" << m_procs << '\n';
    if (m_chk) {
      mol << "%Chk=checkpoint.chk\n";
    }
    if (m_useAntG) {
      if (m_l101) {
        mol << "%Subst L101 .\n";
      }
      if (m_l103) {
        mol << "%Subst L103 .\n";
      }
      if (m_l502) {
        mol << "%Subst L502 .\n";
      }
      if (m_l703) {
        mol << "%Subst L703 .\n";
      }
    }

    // Now specify the job type etc
    //mol << "#n " << getTheoryType(m_theoryType); // ORIGINAL COMMENTED BY C.SALGADO
    mol << "#p ";

    if (m_UHF) {
      mol << "u";
    }

    mol << getTheoryType(m_theoryType);

    // Not all theories have a basis set
    //if (m_theoryType != AM1 && m_theoryType != PM3) // ORIGINAL COMMENTED BY C.SALGADO
    //  mol << '/' << getBasisType(m_basisType); // ORIGINAL COMMENTED BY C.SALGADO
    mol << "/gen pseudo=read ";

    mol << "Scf=(conver="<<ui.scfConverSpin->value();

    if (ui.scfMaxCycleSpin->isEnabled()) {
      mol << ",MaxCycle="<<ui.scfMaxCycleSpin->value();
    }

    if (m_scfnosymm) {
      mol << ",nosymm";
    }
    if (m_scfnodamp) {
      mol << ",nodamp";
    }
    if (m_scfnovaracc) {
      mol << ",novaracc";
    }
    mol << ") ";

    if (m_opt) {
      mol << "Opt=("<<getoptAccuracy(m_optAccuracy);
      if (ui.optmaxcyclesSpin->isEnabled()) {
        mol << ",maxcycles="<<ui.optmaxcyclesSpin->value()<<") ";
      }
    }

    if (m_force) {
      mol << "Force ";
    }

    if (m_globalnosymm) {
      mol << "nosymm";
    }

    //mol << "\n";

    // Now for the calculation type
    //mol << ' ' << getCalculationType(m_calculationType); // ORIGINAL COMMENTED BY C.SALGADO



    // Output parameters for some programs
    //mol << m_output;

    // Title line
    // Gather options:
    if(m_title.isEmpty()){
      QString title(ui.titleLine->text());
      if (title.isEmpty())
        title = generateJobTitle();
      m_title=title;
    }
    mol << "\n\n" << m_title << "\n\n";

    // Now for the charge and multiplicity
    mol << m_charge << ' ' << m_multiplicity << '\n';

    // Now to output the actual molecular coordinates
    // Cartesian coordinates
    if (m_molecule && m_coordType == CARTESIAN) {
      QTextStream mol(&buffer);
      //QList<Core::Atom *> atoms = m_molecule->atoms();
      //QList<Core::AtomTemplate *> atoms = m_molecule->atoms();
      //Core::AtomTemplate<m_molecule>;
      //QList<Core::Atom *> atoms = m_molecule->atoms();
      //if (m_molecule) {
      //QList<Core::Atom *> atoms = QList<Core::Atom *>()<<m_molecule->atom(0);
      //QList<Core::Atom> atoms = QList<Core::Atom>()<<m_molecule->atom(0);
      //QList<Core::Atom> atoms = m_molecule->atoms();
      //new ValidateStorage m_validate;
      //m_validate = ValidateStorage();
      //m_validate->atoms = {};
      //ValidateStorage *temp_validate = new ValidateStorage();
      m_validate->atoms.clear();
      //ValidateStorage *m_validate(new ValidateStorage);
      //m_validate->atoms.removeAll();
      //m_validate->atoms.empty();
      AtomStruct atom;
      for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
          atom.atomicNumber = m_molecule->atom(i).atomicNumber();
          atom.pos.x() = m_molecule->atom(i).position3d().x();
          atom.pos.y() = m_molecule->atom(i).position3d().y();
          atom.pos.z() = m_molecule->atom(i).position3d().z();

          m_validate->atoms << atom;
          //qDebug()<< "i,atom(i) ="<<i<<",("<<atom.pos.x()<<","<<atom.pos.y()<<","<<atom.pos.x()<<")";
      }
      //QVector<AtomStruct> atoms = m_molecule->atoms();
      //qDebug()<< m_validate->atoms;
      QVector<AtomStruct> allatoms(m_validate->atoms);
      /*
      for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
        Core::Atom atom = m_molecule->atom(i);
        //atom = m_molecule->atom(i);
        file += QString("%1 %2 %3 %4 %5\n")
            .arg(Core::Elements::symbol(atoms(i).atomicNumber()), -3)
            .arg(static_cast<float>(atoms(i).atomicNumber()), 5, 'f', 1)
            .arg(atoms(i).position3d().x(), 9, 'f', 5)
            .arg(atoms(i).position3d().y(), 9, 'f', 5)
            .arg(atoms(i).position3d().z(), 9, 'f', 5);
      //}
      */
      //}

      //foreach (AtomStruct atom, atoms) {
      foreach (const AtomStruct &atom, allatoms){
        mol << qSetFieldWidth(3) << left
            //<< QString(OpenBabel::etab.GetSymbol(atom->atomicNumber()))
            //<< QString(Elements::symbol(atom->atomicNumber()))
            << QString(Elements::symbol(atom.atomicNumber))
            << qSetFieldWidth(15) << qSetRealNumberPrecision(5) << forcepoint
            //<< fixed << right << atom->pos()->x() << atom->pos()->y()
            //<< atom->pos()->z()
            << fixed << right << atom.pos.x() << atom.pos.y()
            << atom.pos.z()
            //<< fixed << right << atom.position3d().x() << atom.position3d().y()
            //<< atom.position3d().z()
            << qSetFieldWidth(0) << '\n';
        //qDebug()<< "i,atom(i) ="<<",("<<atom.pos.x()<<","<<atom.pos.y()<<","<<atom.pos.x()<<")";
      }
    //}
      mol << '\n';
    //}

    //---------------------------------------------------------------------------
    //------ IN PRINCIPLE, AVOID USING ZMATRIX ----------------------------------
    //------ BECAUSE OF COMPATIBILITY BETWEEN OLD SIMUNEANTINPUT -----------------
    //------ IN AVOGADRO1 AND NEWER ONE IN AVOGADRO2 ----------------------------
    //---------------------------------------------------------------------------
    /*
    // Z-matrix
    else if (m_molecule && m_coordType == ZMATRIX) {
      QTextStream mol(&buffer);
      OpenBabel::OBAtom *a, *b, *c;
      double r, w, t;

      // Taken from OpenBabel's gzmat file format converter
      std::vector<OpenBabel::OBInternalCoord*> vic;
      vic.push_back((OpenBabel::OBInternalCoord*)NULL);
      OpenBabel::OBMol obmol = m_molecule->OBMol();
      FOR_ATOMS_OF_MOL(atom, &obmol)
        vic.push_back(new OpenBabel::OBInternalCoord);
      CartesianToInternal(vic, obmol);

      foreach (Atom *atom, m_molecule->atoms()) {
        a = vic[atom->index()+1]->_a;
        b = vic[atom->index()+1]->_b;
        c = vic[atom->index()+1]->_c;

        mol << qSetFieldWidth(3) << left
            << QString(OpenBabel::etab.GetSymbol(atom->atomicNumber()))
            << qSetFieldWidth(0);
        if (atom->index() > 0)
          mol << ' ' << a->GetIdx() << " B" << atom->index();
        if (atom->index() > 1)
          mol << ' ' << b->GetIdx() << " A" << atom->index();
        if (atom->index() > 2)
          mol << ' ' << c->GetIdx() << " D" << atom->index();
        mol << '\n';
      }

      mol << "Variables:" << endl;
      foreach (Atom *atom, m_molecule->atoms()) {
        r = vic[atom->index()+1]->_dst;
        w = vic[atom->index()+1]->_ang;
        if (w < 0.0)
          w += 360.0;
        t = vic[atom->index()+1]->_tor;
        if (t < 0.0)
          t += 360.0;
        if (atom->index() > 0)
          mol << "B" << atom->index() << qSetFieldWidth(15)
              << qSetRealNumberPrecision(5) << forcepoint << fixed << right
              << r << qSetFieldWidth(0) << '\n';
        if (atom->index() > 1)
          mol << "A" << atom->index() << qSetFieldWidth(15)
              << qSetRealNumberPrecision(5) << forcepoint << fixed << right
              << w << qSetFieldWidth(0) << '\n';
        if (atom->index() > 2)
          mol << "D" << atom->index() << qSetFieldWidth(15)
              << qSetRealNumberPrecision(5) << forcepoint << fixed << right
              << t << qSetFieldWidth(0) << '\n';
      }
      mol << '\n';
      foreach(OpenBabel::OBInternalCoord *c, vic)
        delete c;
    }
    else if (m_molecule && m_coordType == ZMATRIX_COMPACT)
    {
      QTextStream mol(&buffer);
      OBAtom *a, *b, *c;
      double r, w, t;

      // Taken from OpenBabel's gzmat file format converter
      std::vector<OBInternalCoord*> vic;
      vic.push_back((OBInternalCoord*)NULL);
      OpenBabel::OBMol obmol = m_molecule->OBMol();
      FOR_ATOMS_OF_MOL(atom, &obmol)
        vic.push_back(new OBInternalCoord);
      CartesianToInternal(vic, obmol);

      FOR_ATOMS_OF_MOL(atom, &obmol)
      {
        a = vic[atom->GetIdx()]->_a;
        b = vic[atom->GetIdx()]->_b;
        c = vic[atom->GetIdx()]->_c;
        r = vic[atom->GetIdx()]->_dst;
        w = vic[atom->GetIdx()]->_ang;
        if (w < 0.0)
          w += 360.0;
        t = vic[atom->GetIdx()]->_tor;
        if (t < 0.0)
          t += 360.0;

        mol << qSetFieldWidth(3) << left << QString(etab.GetSymbol(atom->GetAtomicNum()))
            << qSetFieldWidth(6) << right;
        if (atom->GetIdx() > 1)
          mol << a->GetIdx() << qSetFieldWidth(15)
          << qSetRealNumberPrecision(5) << forcepoint << fixed << right << r;
        if (atom->GetIdx() > 2)
          mol << qSetFieldWidth(6) << right << b->GetIdx() << qSetFieldWidth(15)
          << qSetRealNumberPrecision(5) << forcepoint << fixed << right << w;
        if (atom->GetIdx() > 3)
          mol << qSetFieldWidth(6) << right << c->GetIdx() << qSetFieldWidth(15)
          << qSetRealNumberPrecision(5) << forcepoint << fixed << right << t;
        mol << qSetFieldWidth(0) << '\n';
      }
      mol << '\n';
      foreach(OpenBabel::OBInternalCoord *c, vic)
        delete c;
        */
      //-------------------------------------------------------------------------------
      //-------- END COMMENTING THE Z-MATRIX PART. REASONS WRITTEN ABOVE. -------------
      //-------------------------------------------------------------------------------
    }

    //---------------------------------------------------------------------------------
    //----------- BASIS START ---------------------------------------------------------
    //---------------------------------------------------------------------------------
    mol<<m_basisTotalText<<"\n";
    mol<<m_pseudoTotalText<<"\n\n\n";
    //---------------------------------------------------------------------------------
    //------------ END BASIS ----------------------------------------------------------
    //---------------------------------------------------------------------------------
    return buffer;
  }

  //-----------------------------------------------------------------------------------------
  //------ FUNCTIONS TO EDIT THE CUSTOM .INI ANT.G INPUT FILE -------------------------------
  //-----------------------------------------------------------------------------------------
  // THERE ARE 4 TYPES OF WIDGETS USEFUL TO DEVELOP THE .INI BUILDER
  //  connect(ui.procSpin, SIGNAL(valueChanged(int)),
  //    this, SLOT(setProcs(int)));
  //  connect(ui.outputCombo, SIGNAL(currentIndexChanged(int)),
  //    this, SLOT(setOutput(int)));
  //  connect(ui.checkpointCheck, SIGNAL(stateChanged(int)),
  //    this, SLOT(setChk(int)));
  //  connect(ui.coordCombo, SIGNAL(currentIndexChanged(int)),
  //    this, SLOT(setCoords(int)));
  //  connect(ui.previewcomText, SIGNAL(textChanged()),
  //    this, SLOT(previewEdited()));

    void SimuneAntInputDialog::sethamiltonCheck(int n)
    {
      if (n) m_hamiltonCheck = true;
      else m_hamiltonCheck = false;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setmullikenCheck(int n)
    {
      if (n) m_mullikenCheck = true;
      else m_mullikenCheck = false;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setleaddosCheck(int n)
    {
      if (n) m_leaddosCheck = true;
      else m_leaddosCheck = false;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::sethtransmCheck(int n)
    {
      if (n) m_htransmCheck = true;
      else m_htransmCheck = false;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::settype1Combo(int n)
    {
      switch (n)
      {
        case 0:
          //m_type1Combo = "  TYPE1 = BETHE";
          m_type1Combo = BETHE;
          break;
        case 1:
          m_type1Combo = GRAPHENE;
          break;
        case 2:
          m_type1Combo = ONEDLEAD;
          break;
        case 3:
          m_type1Combo = GHOST;
          break;
        default:
          m_type1Combo = GHOST;
      }
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::settype2Combo(int n)
    {
      switch (n)
      {
      case 0:
        //m_type2Combo = "  TYPE1 = BETHE";
        m_type2Combo = BETHE;
        break;
      case 1:
        m_type2Combo = GRAPHENE;
        break;
      case 2:
        m_type2Combo = ONEDLEAD;
        break;
      case 3:
        m_type2Combo = GHOST;
        break;
      default:
        m_type2Combo = GHOST;
      }
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setblpar1Combo(int n)
    {
      switch (n)
      {
        case 0:
          m_blpar1Combo = lsdacrenbs;
          break;
        case 1:
          m_blpar1Combo = lsda6s;
          break;
        case 2:
          m_blpar1Combo = papacon;
          break;
        case 3:
          m_blpar1Combo = papaconsd;
          break;
        case 4:
          m_blpar1Combo = papaconold;
          break;
        default:
          m_blpar1Combo = lsdacrenbs;
      }
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setblpar2Combo(int n)
    {
      switch (n)
      {
      case 0:
        m_blpar2Combo = lsdacrenbs;
        break;
      case 1:
        m_blpar2Combo = lsda6s;
        break;
      case 2:
        m_blpar2Combo = papacon;
        break;
      case 3:
        m_blpar2Combo = papaconsd;
        break;
      case 4:
        m_blpar2Combo = papaconold;
        break;
      default:
        m_blpar2Combo = lsdacrenbs;
      }
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnatomel1Spin(int n)
    {
      if (n > 0)
        m_natomel1Spin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnatomel2Spin(int n)
    {
      if (n > 0)
        m_natomel2Spin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnembed1Spin(int n)
    {
      if (n > 0)
        m_nembed1Spin = n;
      updateMolecBasisInput();
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnembed2Spin(int n)
    {
      if (n > 0)
        m_nembed2Spin = n;
      updateMolecBasisInput();
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnspinlockSpin(int n)
    {
      if (n > 0)
        m_nspinlockSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnalphaSpin(int n)
    {
      if (n > 0)
        m_nalphaSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnbetaSpin(int n)
    {
      if (n > 0)
        m_nbetaSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setnchannelsSpin(int n)
    {
      if (n > 0)
        m_nchannelsSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setldosbegSpin(int n)
    {
      if (n > 0)
        m_ldosbegSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setldosendSpin(int n)
    {
      if (n > 0)
        m_ldosendSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setrtmbegSpin(int n)
    {
      if (n > 0)
        m_rtmbegSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setrtmendSpin(int n)
    {
      if (n > 0)
        m_rtmendSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setpaccSpin(int n)
    {
      if (n > 0)
        m_paccSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setchargeaccSpin(int n)
    {
      if (n > 0)
        m_chargeaccSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setfermiaccSpin(int n)
    {
      if (n > 0)
        m_fermiaccSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setselfaccSpin(int n)
    {
      if (n > 0)
        m_selfaccSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setetaSpin(int n)
    {
      if (n > 0)
        m_etaSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setslSpin(int n)
    {
      if (n > 0)
        m_slSpin = n;
      updatePreviewIniText();
    }

    /*
    void SimuneAntInputDialog::setssmSpin(int n)
    {
      if (n > 0)
        m_ssmSpin = n;
      updatePreviewIniText();
    }
    */

    void SimuneAntInputDialog::setswoffsplSpin(int n)
    {
      if (n > 0)
        m_swoffsplSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setalphaSpin(double n)
    {
      //if (n > 0)
      m_alphaSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setoverlapSpin(double n)
    {
      //if (n > 0)
      m_overlapSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setbiasvoltSpin(double n)
    {
      //if (n > 0)
      m_biasvoltSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setqexcessSpin(double n)
    {
      //if (n > 0)
      m_qexcessSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setfermistartSpin(double n)
    {
      //if (n > 0)
      m_fermistartSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setestepSpin(double n)
    {
      //if (n > 0)
      m_estepSpin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setew1Spin(double n)
    {
      //if (n > 0)
      m_ew1Spin = n;
      updatePreviewIniText();
    }

    void SimuneAntInputDialog::setew2Spin(double n)
    {
      //if (n > 0)
      m_ew2Spin = n;
      updatePreviewIniText();
    }

    /*
    void SimuneAntInputDialog::setOutput(int n)
    {
      switch (n)
      {
        case 1:
          m_output = " gfprint pop=full";
          break;
        case 2:
          m_output = " gfoldprint pop=full";
          break;
        default:
          m_output = "";
      }
      updatePreviewComText();
    }

    void SimuneAntInputDialog::setChk(int n)
    {
      if (n) m_chk = true;
      else m_chk = false;
      updatePreviewComText();
    }
    */

    /*
    void SimuneAntInputDialog::previewEdited()
    {
      // Determine if the preview text has changed from the form generated
      if(ui.previewcomText->toPlainText() != generateInputDeck())
        deckDirty(true);
      else
        deckDirty(false);
    }
    */
  //-----------------------------------------------------------------------------------------

    QString SimuneAntInputDialog::generateInputIniDeck()
    {
      // Generate an input deck based on the settings of the dialog
      QString buffer;
      QTextStream mol(&buffer);

      if (m_hamiltonCheck) {
        mol << "HAMILTON\n";
      }else{
        mol << "!  HAMILTON\n";
      }

      if (m_mullikenCheck) {
        mol << "MULLIKEN\n";
      }else{
        mol << "!  MULLIKEN\n";
      }

      if (0.0 <= m_alphaSpin <= 0.1)
        mol << "  ALPHA      =    " << m_alphaSpin << '\n';
      else
        mol << "  ALPHA      =    " << "0.02" << '\n';

      if (m_paccSpin != -1)
        mol << "  PACC      =    1.0D-" << m_paccSpin << '\n';
      else
        mol << "  PACC      =    1.0D-8\n";

      if (m_chargeaccSpin != -1)
        mol << "  CHARGEACC      =    1.0D-" << m_chargeaccSpin << '\n';
      else
        mol << "  CHARGEACC      =    1.0D-6\n";

      if (m_fermiaccSpin != -1)
        mol << "  FERMIACC      =    1.0D-" << m_fermiaccSpin << '\n';
      else
        mol << "  FERMIACC      =    1.0D-6\n";

      if (m_selfaccSpin != -1)
        mol << "  SELFACC      =    1.0D-" << m_selfaccSpin << '\n';
      else
        mol << "!  SELFACC      =    1.0D-6\n";

      //--- BIASVOLT ---
      //mol << "  BIASVOLT      =    " << m_biasvoltSpin << '\n';
      mol << "  BIASVOLT      =    "<< QString::number((double) m_biasvoltSpin, 'f',1) << "D0\n";

      //--- QEXCESS ---
      //mol << "  QEXCESS      =    " << m_qexcessSpin << '\n';
      mol << "  QEXCESS      =    "<< QString::number((double) m_qexcessSpin, 'f',1) << "D0\n";


      if (m_etaSpin != -1)
        mol << "  ETA      =    1.0D-" << m_etaSpin << '\n';
      else
        mol << "  ETA      =    1.0D-6\n";

      if (m_slSpin != -1)
        mol << "  SL      =    1.0D-" << m_slSpin << '\n';
      else
        mol << "!  SL      =    1.0D-3\n";

      /*
      if (m_ssmSpin != -1)
        mol << "  SSM      =    1.0D-" << m_ssmSpin << '\n';
      else
        mol << "!  SSM      =    1.0D-4\n";
      */

      //--- FERMISTART ---
      //mol << "  FERMISTART      =    " << m_fermistartSpin << '\n';
      if (m_fermistartSpin != 9999.0)
        //mol << "  FERMISTART      =    " << m_fermistartSpin << "D0\n";
        mol << "  FERMISTART      =    "<< QString::number((double) m_fermistartSpin, 'f',1) << "D0\n";
      else
        mol << "!  FERMISTART      =    -5.0D0\n";


      if (m_swoffsplSpin != 1)
        mol << "  SWOFFSPL      =    1.0D-" << m_swoffsplSpin << '\n';
      else
        mol << "!  SWOFFSPL      =    1.0D-3\n";


      mol << "  TYPE1      =    " << getBetheType(m_type1Combo) << '\n';
      mol << "  TYPE2      =    " << getBetheType(m_type2Combo) << '\n';

      mol << "  BLPAR1      =    " << getBlpar(m_blpar1Combo) << '\n';
      mol << "  BLPAR2      =    " << getBlpar(m_blpar2Combo) << '\n';

      if (0.0 <= m_overlapSpin <= 1.0)
        //mol << "  OVERLAP      =    " << m_overlapSpin << '\n';
        mol << "  OVERLAP      =    "<< QString::number((double) m_overlapSpin, 'f',1) << "D0\n";
      else if (m_overlapSpin == -1.0)
        mol << "  OVERLAP      =    " << "-1.0" << 'D0\n';
      else
        mol << "!  OVERLAP      =    " << "0.0" << 'D0\n';


      if (m_nembed1Spin >= 0)
        mol << "  NEMBED1      =    " << m_nembed1Spin << '\n';
      else
        mol << "!  NEMBED1      =    0\n";

      if (m_nembed2Spin >= 0)
        mol << "  NEMBED2      =    " << m_nembed2Spin << '\n';
      else
        mol << "!  NEMBED2      =    0\n";

      if (m_natomel1Spin >= 0)
        mol << "  NATOMEL1      =    " << m_natomel1Spin << '\n';
      else
        mol << "!  NATOMEL1      =    0\n";

      if (m_natomel2Spin >= 0)
        mol << "  NATOMEL2      =    " << m_natomel2Spin << '\n';
      else
        mol << "!  NATOMEL2      =    0\n";


      if (m_nalphaSpin >= 0)
        mol << "  NALPHA      =    " << m_nalphaSpin << '\n';
      else
        mol << "!  NALPHA      =    0\n";

      if (m_nbetaSpin >= 0)
        mol << "  NBETA      =    " << m_nbetaSpin << '\n';
      else
        mol << "!  NBETA      =    0\n";


      if (m_htransmCheck) {
        mol << "HTRANSM\n";
      }else{
        mol << "!  HTRANSM\n";
      }

      if (0 <= m_estepSpin)
        mol << "  ESTEP      =    1.0D-" << m_estepSpin << '\n';
      else
        mol << "  ESTEP      =    1.0D-2" << '\n';

      if (m_ew1Spin <= m_ew2Spin){
        //mol << "  EW1      =    " << m_ew1Spin << "D0\n";
        //mol << "  EW2      =    " << m_ew2Spin << "D0\n";
        mol << "  EW1      =    " << QString::number((double) m_ew1Spin, 'f',1) << "D0\n";
        mol << "  EW2      =    " << QString::number((double) m_ew2Spin, 'f',1) << "D0\n";
      }else{
        //mol << "!  EW1      =    " << m_ew1Spin << "D0\n";
        //mol << "!  EW2      =    " << m_ew2Spin << "D0\n";
        mol << "!  EW1      =    " << QString::number((double) m_ew1Spin, 'f',1) << "D0\n";
        mol << "!  EW2      =    " << QString::number((double) m_ew2Spin, 'f',1) << "D0\n";
      }

      if (m_ldosbegSpin > 0 && m_ldosendSpin > 0){
        if (m_ldosbegSpin <= m_ldosendSpin){
          mol << "  LDOS_BEG      =    " << m_ldosbegSpin << '\n';
          mol << "  LDOS_END      =    " << m_ldosendSpin << '\n';
        }else{
          mol << "!  LDOS_BEG      =    " << m_ldosbegSpin << '\n';
          mol << "!  LDOS_END      =    " << m_ldosendSpin << '\n';
        }
      }else{
        mol << "!  LDOS_BEG      =    " << m_ldosbegSpin << '\n';
        mol << "!  LDOS_END      =    " << m_ldosendSpin << '\n';
      }

      if (m_nchannelsSpin > 0)
        mol << "  NCHANNELS      =    " << m_nchannelsSpin << '\n';
      else
        mol << "!  NCHANNELS      =    0\n";

      if (m_leaddosCheck) {
        mol << "LEADDOS\n";
      }else{
        mol << "!  LEADDOS\n";
      }

      if (m_rtmbegSpin > 0 && m_rtmendSpin > 0){
        if (m_rtmbegSpin <= m_rtmendSpin){
          mol << "  RTM_BEG      =    " << m_rtmbegSpin << '\n';
          mol << "  RTM_END       =    " << m_rtmendSpin << '\n';
        }else{
          mol << "!  RTM_BEG      =    " << m_rtmbegSpin << '\n';
          mol << "!  RTM_END      =    " << m_rtmendSpin << '\n';
        }
      }

      return buffer;
    }

    QString SimuneAntInputDialog::getBetheType(typeBetheCombo t)
    {
      // Translate the enum to text for the output generation
      switch (t)
      {
        case BETHE:
          return "BETHE";
        case GRAPHENE:
          return "GRAPHENE";
        case ONEDLEAD:
          return "ONEDLEAD";
      case GHOST:
        return "GHOST";
        default:
          return "GHOST";
      }
    }

    QString SimuneAntInputDialog::getBlpar(blparCombo t)
    {
      // Translate the enum to text for the output generation
      switch (t)
      {
        case lsdacrenbs:
          return "lsda-crenbs";
        case lsda6s:
          return "lsda-6s";
        case papacon:
          return "Papacon";
        case papaconsd:
          return "Papacon-sd";
        case papaconold:
          return "Papacon-old";
        default:
          return "lsda-crenbs";
      }
    }
  //---------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------

  QString SimuneAntInputDialog::getCalculationType(calculationType t)
  {
      qDebug()<<"I am in getCalculationType";
    // Translate the enum to text for the output generation
    switch (t)
    {
      case SP:
        return "SP";
      case OPT:
        return "Opt";
      case FREQ:
        return "Opt Freq";
      default:
        return "SP";
    }
  }

  /*
  QString SimuneAntInputDialog::getTheoryType(theoryType t)
  {
      qDebug()<<"I am in getTheoryType";
    // Translate the enum to text for the output generation
    switch (t)
    {
      case AM1:
        return "AM1";
      case PM3:
        return "PM3";
      case RHF:
        return "RHF";
      case B3LYP:
        return "B3LYP";
      case MP2:
        return "MP2";
      case CCSD:
        return "CCSD";
      default:
        return "RHF";
    }
  }
  */

  QString SimuneAntInputDialog::getTheoryType(theoryType t)
  {
      qDebug()<<"I am in getTheoryType";
    // Translate the enum to text for the output generation
    switch (t)
    {
      case lsda:
        return "lsda";
      case bpbe:
        return "bpbe";
      case blyp:
        return "blyp";
      case B3LYP:
        return "B3LYP";
      case hseh1pbe:
        return "hseh1pbe";
      default:
        return "lsda";
    }
  }

  QString SimuneAntInputDialog::getoptAccuracy(optAccuracyCombo t)
  {
      qDebug()<<"I am in getoptAccuracy";
    // Translate the enum to text for the output generation
    switch (t)
    {
      case loose:
        return "loose";
      case tight:
        return "tight";
      case verytight:
        return "verytight";
      default:
        return "loose";
    }
  }

  QString SimuneAntInputDialog::getBasisType(basisType t)
  {
      qDebug()<<"I am in getBasisType";
    // Translate the enum to text for the output generation
    switch (t)
    {
      case minimal6s:
        return "lsda6S";
      case CRENBS:
        return "CRENBS";
      case LANL2DZ:
        return "LANL2DZ";
      case STO3G:
        return "STO-3G";
      case B321G:
        return "3-21G";
      case B631Gd:
        return "6-31G(d)";
      case B631Gdp:
        return "6-31G(d,p)";
      default:
        return "6-31G(d)";
    }
  }

  void SimuneAntInputDialog::updateMolecBasisInput(){
      qDebug()<<"I am in updateMolecBasisInput";

      for (int i = 0; i < ui.atomtypeMolecCombo->count(); ++i) {
        ui.atomtypeMolecCombo->removeItem(i);
      }


      //----------------------------------------------------------------------------------------------------
      //------------------- STRUCTURING ELEMENTS -----------------------------------------------------------
      //----------------------------------------------------------------------------------------------------
      QVector<QString> m_elementsInMolecStr;
      //QVector<int> m_elementsInMolecNr;
      //QVector<int> m_firstAtominElement;
      //QVector<int> m_lastAtominElement;

      QString m_elementsInElecOneStr;
      QString m_elementsInElecTwoStr;

      //m_elementsInMolecStr.clear();
      m_elementsInMolecNr.clear();
      m_firstAtominElement.clear();
      m_lastAtominElement.clear();

      int j;
      int k=0;
      for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
        j=i+1;
        if ((i<m_nembed1Spin) && (i>=0)){
            m_elementsInElecOneNr=m_molecule->atom(i).atomicNumber();
            m_elementsInElecOneStr=QString(Elements::symbol(m_molecule->atom(i).atomicNumber()));
        }
        if ((i>=m_molecule->atomCount()-m_nembed2Spin) && (i<m_molecule->atomCount())){
            m_elementsInElecTwoNr=m_molecule->atom(i).atomicNumber();
            m_elementsInElecTwoStr=QString(Elements::symbol(m_molecule->atom(i).atomicNumber()));
        }
        if ((i>m_nembed1Spin-1) && (i<m_molecule->atomCount()-m_nembed2Spin)){
          if (!(m_elementsInMolecNr.contains(m_molecule->atom(i).atomicNumber()))){
            qDebug()<<"k = "<<k;
            m_firstAtominElement.append(j);
            //elementsInMolecNr[k]=m_molecule->atom(i).atomicNumber();
            m_elementsInMolecNr.append(m_molecule->atom(i).atomicNumber());
            //atom.atomicNumber = m_molecule->atom(i).atomicNumber();
            //elementsInMolecStr[k]=QString(Elements::symbol(m_molecule->atom(i).atomicNumber()));
            m_elementsInMolecStr.append(QString(Elements::symbol(m_molecule->atom(i).atomicNumber())));
            qDebug()<<"m_elementsInMolecStr(k) = ";
            qDebug()<<m_elementsInMolecStr[k];
            //qDebug()<< "i,atom(i) ="<<i<<",("<<atom.pos.x()<<","<<atom.pos.y()<<","<<atom.pos.x()<<")";
            k++;
          }
        }
      }
      if (m_firstAtominElement.size()>1){
        for (int i = 0; i < m_firstAtominElement.size()-1; ++i) {
          //m_lastAtominElement[i]=m_firstAtominElement[i+1]-1;
          m_lastAtominElement.append(m_firstAtominElement[i+1]-1);
          qDebug()<<"m_lastAtominElement["<<i<<"] = "<<m_lastAtominElement[i];
        }
      }
      //m_lastAtominElement[m_firstAtominElement.size()-1]=k;
      m_lastAtominElement.append(m_molecule->atomCount()-m_nembed2Spin);
      qDebug()<<"m_lastAtominElement["<<m_lastAtominElement.size()-1<<"] = "<<k;
      k=0;
      //----------------------------------------------------------------------------------------------------
      //----------------- END STRUCTURING ELEMENTS ---------------------------------------------------------
      //----------------------------------------------------------------------------------------------------

      for (int i = 0; i < m_elementsInMolecStr.size(); ++i) {
        qDebug()<<"i = "<<i;
        qDebug()<<"m_elementsInMolecStr(i) = "<<m_elementsInMolecStr[i];
        ui.atomtypeMolecCombo->addItem(m_elementsInMolecStr[i]);
      }
  }


  void SimuneAntInputDialog::on_setAutoBasisButton_clicked()
  {
      qDebug()<<"I am in on_setAutoBasisButton_clicked";
      // NOW TO CONSIDER HALF OF THE ATOMS BELONGING TO EACH ELECTRODE.
      qDebug()<<"m_molecule->atomCount() = "<<m_molecule->atomCount();
      qDebug()<<"qFloor((m_molecule->atomCount()/2)) = "<<qreal((m_molecule->atomCount()))/2;
      qDebug()<<"qFloor((m_molecule->atomCount()/2)) = "<<qFloor(qreal((m_molecule->atomCount()))/2);
      //setnatomel1Spin((int)(m_molecule->atomCount()/2));
      //setnatomel2Spin((int)(m_molecule->atomCount()/2));
      setnatomel1Spin(qFloor(qreal((m_molecule->atomCount()/2))));
      setnatomel2Spin(qFloor(qreal((m_molecule->atomCount()/2))));
      ui.natomel1Spin->setValue(m_natomel1Spin);
      ui.natomel2Spin->setValue(m_natomel2Spin);
      setnembed1Spin(m_natomel1Spin-1);
      setnembed2Spin(m_natomel2Spin-1);
      ui.nembed1Spin->setValue(m_nembed1Spin);
      ui.nembed2Spin->setValue(m_nembed2Spin);

      ui.ldosbegSpin->setValue(1);
      ui.ldosendSpin->setValue(m_molecule->atomCount());

      getLoadFullBasisType(ui.basisMolecCombo->currentIndex());
      getLoadFullPseudoType(ui.basisMolecCombo->currentIndex());

      updateTitle();
      getTitle();
      ui.previewcomText->setText(generateInputDeck());

  //#ifndef QT_NO_CURSOR
  //    QApplication::setOverrideCursor(Qt::ArrowCursor);
  //#endif
  }

  void SimuneAntInputDialog::on_setBasisButton_clicked()
  {
      qDebug()<<"I am in on_setBasisButton_clicked";
      // NOW TO CONSIDER HALF OF THE ATOMS BELONGING TO EACH ELECTRODE.

      getLoadFullBasisType(ui.basisMolecCombo->currentIndex());
      getLoadFullPseudoType(ui.basisMolecCombo->currentIndex());

      ui.previewcomText->setText(generateInputDeck());

  //#ifndef QT_NO_CURSOR
  //    QApplication::setOverrideCursor(Qt::ArrowCursor);
  //#endif
  }

  //void SimuneAntInputDialog::on_basisMolecCombo_currentIndexChanged(int index)
  //{
  //    getLoadFullBasisType(index);
  //    getLoadFullPseudoType(index);
  //}

  /*
  void Avogadro::QtPlugins::SimuneAntInputDialog::on_basisMolecCombo_currentIndexChanged(const QString &arg1)
  {
      getLoadFullBasisType();
  }
  */
  //QString SimuneAntInputDialog::getLoadFullBasisType(){
  //
  //}

  //QString SimuneAntInputDialog::getLoadFullBasisType(basisType t)
  void SimuneAntInputDialog::getLoadFullBasisTypeOld(int n)
  {
      qDebug()<<"I am in getLoadFullBasisType";

    QString alacant = qgetenv("ALACANT");

    //QString basisFile = alacant + "/BASDAT/";
    //QString basisFileName;

    //QVector<QString> basisonlyelement;

    /*
    AtomStruct atom;
    for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
        atom.atomicNumber = m_molecule->atom(i).atomicNumber();
        atom.pos.x() = m_molecule->atom(i).position3d().x();
        atom.pos.y() = m_molecule->atom(i).position3d().y();
        atom.pos.z() = m_molecule->atom(i).position3d().z();

        m_validate->atoms << atom;
        //qDebug()<< "i,atom(i) ="<<i<<",("<<atom.pos.x()<<","<<atom.pos.y()<<","<<atom.pos.x()<<")";
    }
    //QVector<AtomStruct> atoms = m_molecule->atoms();
    //qDebug()<< m_validate->atoms;
    QVector<AtomStruct> allatoms(m_validate->atoms);
    */
    /*
    for (size_t i = 0; i < m_molecule->atomCount(); ++i) {
      Core::Atom atom = m_molecule->atom(i);
      //atom = m_molecule->atom(i);
      file += QString("%1 %2 %3 %4 %5\n")
          .arg(Core::Elements::symbol(atoms(i).atomicNumber()), -3)
          .arg(static_cast<float>(atoms(i).atomicNumber()), 5, 'f', 1)
          .arg(atoms(i).position3d().x(), 9, 'f', 5)
          .arg(atoms(i).position3d().y(), 9, 'f', 5)
          .arg(atoms(i).position3d().z(), 9, 'f', 5);
    //}
    */
    //}

/*    //foreach (AtomStruct atom, atoms) {
    foreach (const AtomStruct &atom, allatoms){
      mol << qSetFieldWidth(3) << left
          //<< QString(OpenBabel::etab.GetSymbol(atom->atomicNumber()))
          //<< QString(Elements::symbol(atom->atomicNumber()))
          << QString(Elements::symbol(atom.atomicNumber))
          << qSetFieldWidth(15) << qSetRealNumberPrecision(5) << forcepoint
          //<< fixed << right << atom->pos()->x() << atom->pos()->y()
          //<< atom->pos()->z()
          << fixed << right << atom.pos.x() << atom.pos.y()
          << atom.pos.z()
          //<< fixed << right << atom.position3d().x() << atom.position3d().y()
          //<< atom.position3d().z()
          << qSetFieldWidth(0) << '\n';
      //qDebug()<< "i,atom(i) ="<<",("<<atom.pos.x()<<","<<atom.pos.y()<<","<<atom.pos.x()<<")";
    }

*/


    //for (size_t i = 0; i < ui.atomtypeMolecCombo->count();++i)

    qDebug()<<"I am in getLoadFullBasisType 1";
    // Translate the enum to text for the output generation
    //QString basType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
    QString basType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
    qDebug()<<"basType"<<basType;
    qDebug()<<"I am in getLoadFullBasisType 2";
    //QString basType;
    //basType=ui.basisMolecCombo->itemText(n);
    /*
    QString basType;
    switch (t)
    {
      case CRENBS:
        basType="CRENBS";
      case lsda6s:
        basType="lsda6S";
      case LANL2DZ:
        basType="LANL2DZ";
      case STO3G:
        basType="STO-3G";
      case B321G:
        basType="3-21G";
      case B631Gd:
        basType="6-31G(d)";
      case B631Gdp:
        basType="6-31G(d,p)";
      default:
        basType="6-31G(d)";
    }
    */



      //QString fileName =
      /*
      QString fullpathfileName =
          QFileDialog::getOpenFileName(
                  this,
                  tr("Open File"),
                  "C:/TEST",
                  //tr("videoss (*.mp4 *.mov *.avi)"));
                  //tr("(*.mp4 *.mov *.avi)"));
                  tr("(*.com)"));
      */
      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeMolecCombo->currentText()+"_"+basType+".dat";
      QString basisfileName;
      QTextStream basisfileStream(&basisfileName);
      basisfileStream << alacant << "/BASDAT/" << ui.atomtypeMolecCombo->currentText() << "_" << basType << ".dat";
      qDebug()<<"basisfileName"<<basisfileName;

      QFileInfo fi(basisfileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "basisfileName" << basisfileName;
      //QFileInfo::basename().toStdString()

      if (!basisfileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile basisFile(basisfileName);
          if (!basisFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(basisfileName)
                                   .arg(basisFile.errorString()));
              return;
          }
          QTextStream in(&basisFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString basisstring = in.readAll();
          qDebug() << "basisstring;";
          qDebug() << basisstring;
          //mol<<basisstring;
          m_basisTotalText.clear();
          //m_basisTotalText+=m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"-"+m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"\n";
          //m_basisTotalText+=QStringLiteral("My magic number is %1. That's all!").arg(i);
          QTextStream(&m_basisTotalText)<<m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]<<"-"<<m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()];
          //m_basisTotalText+=basisstring;
          QTextStream(&m_basisTotalText)<<"\n";
          QTextStream(&m_basisTotalText)<<basisstring<<"****\n";
          basisFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::ArrowCursor);
      #endif
      }
      qDebug() << "SimuneAntInputDialog::getLoadFullBasisType() -> updatePreviewComText();";
      updatePreviewComText();
  }

  //---------------------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------------------

  void SimuneAntInputDialog::getLoadFullBasisType(int n)
  {
      qDebug()<<"I am in getLoadFullBasisType";

    //for (size_t i = 0; i < ui.atomtypeMolecCombo->count();++i)

    //qDebug()<<"I am in ";
    // Translate the enum to text for the output generation

    QString basisMolecstring = getBasisMolecString();
    QString basisElecOnestring = getBasisElecOneString();
    QString basisElecTwostring = getBasisElecTwoString();
    //mol<<basisstring;
    m_basisTotalText.clear();
    //m_basisMolecTotalText+=m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"-"+m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"\n";
    //m_basisTotalText+=QStringLiteral("My magic number is %1. That's all!").arg(i);
    QTextStream(&m_basisTotalText)<<"1-"<<m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]-1;
    QTextStream(&m_basisTotalText)<<"\n";
    QTextStream(&m_basisTotalText)<<basisElecOnestring;
    QTextStream(&m_basisTotalText)<<m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]<<"-"<<m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()];
    //m_basisTotalText+=basisstring;
    QTextStream(&m_basisTotalText)<<"\n";
    QTextStream(&m_basisTotalText)<<basisMolecstring;
    QTextStream(&m_basisTotalText)<<m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()]+1<<"-"<<m_molecule->atomCount();
    QTextStream(&m_basisTotalText)<<"\n";
    QTextStream(&m_basisTotalText)<<basisElecTwostring;

    qDebug() << "SimuneAntInputDialog::getLoadFullBasisType() -> updatePreviewComText();";
    updatePreviewComText();
  }

  QString SimuneAntInputDialog::getBasisMolecString(){
      qDebug()<<"I am in getBasisMolecString()";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString basisMolecType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"basisType"<<basisMolecType;

      //QString basType;
      //basType=ui.basisMolecCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeMolecCombo->currentText()+"_"+basisType+".dat";
      QString basisMolecfileName;
      QTextStream basisMolecfileStream(&basisMolecfileName);
      basisMolecfileStream << alacant << "/BASDAT/" << ui.atomtypeMolecCombo->currentText() << "_" << basisMolecType << ".dat";
      qDebug()<<"basisfileName"<<basisMolecfileName;

      QFileInfo fi(basisMolecfileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "basisfileName" << basisMolecfileName;
      //QFileInfo::basename().toStdString()

      if (!basisMolecfileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile basisMolecFile(basisMolecfileName);
          if (!basisMolecFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(basisMolecfileName)
                                   .arg(basisMolecFile.errorString()));
              return "";
          }
          QTextStream in(&basisMolecFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString basisMolecstring = in.readAll();
          basisMolecFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "basisMolecstring;";
          qDebug() << basisMolecstring;
          return basisMolecstring;

      }else{
          return "";
      }
  }

  QString SimuneAntInputDialog::getBasisElecOneString(){
      qDebug()<<"I am in getBasisElecOneString()";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisElecOneCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString basisElecOneType(ui.blpar1Combo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"basisType"<<basisElecOneType;

      //QString basType;
      //basType=ui.basisElecOneCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeElecOneCombo->currentText()+"_"+basisType+".dat";
      QString basisElecOnefileName;
      //basisElecOnefileName = alacant+"/BASDAT/"+ui.atomtypeElecOneCombo->currentText()+"_"+basisElecOneType+".dat";
      QTextStream basisElecOnefileStream(&basisElecOnefileName);
      basisElecOnefileStream << alacant << "/BASDAT/" << m_elementsInElecOneNr << "_" << basisElecOneType << ".dat";
      qDebug()<<"basisfileName"<<basisElecOnefileName;

      QFileInfo fi(basisElecOnefileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "basisfileName" << basisElecOnefileName;
      //QFileInfo::basename().toStdString()

      if (!basisElecOnefileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile basisElecOneFile(basisElecOnefileName);
          if (!basisElecOneFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(basisElecOnefileName)
                                   .arg(basisElecOneFile.errorString()));
              return "";
          }
          QTextStream in(&basisElecOneFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString basisElecOnestring = in.readAll();
          basisElecOneFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "basisElecOnestring;";
          qDebug() << basisElecOnestring;
          return basisElecOnestring;
      }else{
        return "";
      }
  }

  QString SimuneAntInputDialog::getBasisElecTwoString(){
      qDebug()<<"I am in getBasisElecTwoString()";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisElecTwoCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString basisElecTwoType(ui.blpar2Combo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"basisType"<<basisElecTwoType;

      //QString basType;
      //basType=ui.basisElecTwoCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeElecTwoCombo->currentText()+"_"+basisType+".dat";
      QString basisElecTwofileName;
      //basisElecTwofileName = alacant+"/BASDAT/"+ui.atomtypeElecTwoCombo->currentText()+"_"+basisElecTwoType+".dat";
      QTextStream basisElecTwofileStream(&basisElecTwofileName);
      basisElecTwofileStream << alacant << "/BASDAT/" << m_elementsInElecTwoNr << "_"+basisElecTwoType << ".dat";
      qDebug()<<"basisfileName"<<basisElecTwofileName;

      QFileInfo fi(basisElecTwofileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "basisfileName" << basisElecTwofileName;
      //QFileInfo::basename().toStdString()

      if (!basisElecTwofileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile basisElecTwoFile(basisElecTwofileName);
          if (!basisElecTwoFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(basisElecTwofileName)
                                   .arg(basisElecTwoFile.errorString()));
              return "";
          }
          QTextStream in(&basisElecTwoFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString basisElecTwostring = in.readAll();
          basisElecTwoFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "basisElecTwostring;";
          qDebug() << basisElecTwostring;
          return basisElecTwostring;
      }else{
        return "";
      }
  }
  //---------------------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------------------------------------

  void SimuneAntInputDialog::getLoadFullPseudoType(int n)
  {
      qDebug()<<"I am in getLoadFullPseudoType";

    //for (size_t i = 0; i < ui.atomtypeMolecCombo->count();++i)

    //qDebug()<<"I am in ";
    // Translate the enum to text for the output generation

    QString pseudoMolecstring = getPseudoMolecString();
    QString pseudoElecOnestring = getPseudoElecOneString();
    QString pseudoElecTwostring = getPseudoElecTwoString();
    //mol<<pseudostring;
    m_pseudoTotalText.clear();
    //m_pseudoMolecTotalText+=m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"-"+m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()]+"\n";
    //m_pseudoTotalText+=QStringLiteral("My magic number is %1. That's all!").arg(i);
    QTextStream(&m_pseudoTotalText)<<"1-"<<m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]-1;
    QTextStream(&m_pseudoTotalText)<<"\n";
    QTextStream(&m_pseudoTotalText)<<pseudoElecOnestring;
    QTextStream(&m_pseudoTotalText)<<m_firstAtominElement[ui.atomtypeMolecCombo->currentIndex()]<<"-"<<m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()];
    //m_pseudoTotalText+=pseudostring;
    QTextStream(&m_pseudoTotalText)<<"\n";
    QTextStream(&m_pseudoTotalText)<<pseudoMolecstring;
    QTextStream(&m_pseudoTotalText)<<m_lastAtominElement[ui.atomtypeMolecCombo->currentIndex()]+1<<"-"<<m_molecule->atomCount();
    QTextStream(&m_pseudoTotalText)<<"\n";
    QTextStream(&m_pseudoTotalText)<<pseudoElecTwostring;

    qDebug() << "SimuneAntInputDialog::getLoadFullPseudoType() -> updatePreviewComText();";
    updatePreviewComText();
  }

  QString SimuneAntInputDialog::getPseudoMolecString(){
      qDebug()<<"I am in getPseudoMolecString";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString pseudoMolecType(ui.basisMolecCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"pseudoType"<<pseudoMolecType;

      //QString basType;
      //basType=ui.basisMolecCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeMolecCombo->currentText()+"_"+pseudoType+".dat";
      QString pseudoMolecfileName;
      QTextStream pseudoMolecfileStream(&pseudoMolecfileName);
      pseudoMolecfileStream << alacant << "/PSEUDODAT/" << ui.atomtypeMolecCombo->currentText() << "_" << pseudoMolecType << ".dat";

      qDebug()<<"pseudofileName"<<pseudoMolecfileName;

      QFileInfo fi(pseudoMolecfileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "pseudofileName" << pseudoMolecfileName;
      //QFileInfo::basename().toStdString()

      if (!pseudoMolecfileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile pseudoMolecFile(pseudoMolecfileName);
          if (!pseudoMolecFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(pseudoMolecfileName)
                                   .arg(pseudoMolecFile.errorString()));
              return "";
          }
          QTextStream in(&pseudoMolecFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString pseudoMolecstring = in.readAll();
          pseudoMolecFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "pseudoMolecstring;";
          qDebug() << pseudoMolecstring;
          return pseudoMolecstring;

      }else{
          return "";
      }
  }

  QString SimuneAntInputDialog::getPseudoElecOneString(){
      qDebug()<<"I am in getPseudoElecOneString";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisElecOneCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString pseudoElecOneType(ui.blpar1Combo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"pseudoType"<<pseudoElecOneType;

      //QString basType;
      //basType=ui.basisElecOneCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeElecOneCombo->currentText()+"_"+pseudoType+".dat";
      QString pseudoElecOnefileName;
      //pseudoElecOnefileName = alacant+"/PSEUDODAT/"+ui.atomtypeElecOneCombo->currentText()+"_"+pseudoElecOneType+".dat";
      QTextStream(&pseudoElecOnefileName) << alacant << "/PSEUDODAT/" << m_elementsInElecOneNr << "_"+pseudoElecOneType << ".dat";
      qDebug()<<"pseudofileName"<<pseudoElecOnefileName;

      QFileInfo fi(pseudoElecOnefileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "pseudofileName" << pseudoElecOnefileName;
      //QFileInfo::basename().toStdString()

      if (!pseudoElecOnefileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile pseudoElecOneFile(pseudoElecOnefileName);
          if (!pseudoElecOneFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(pseudoElecOnefileName)
                                   .arg(pseudoElecOneFile.errorString()));
              return "";
          }
          QTextStream in(&pseudoElecOneFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString pseudoElecOnestring = in.readAll();
          pseudoElecOneFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "pseudoElecOnestring;";
          qDebug() << pseudoElecOnestring;
          return pseudoElecOnestring;
      }else{
        return "";
      }
  }

  QString SimuneAntInputDialog::getPseudoElecTwoString(){
      qDebug()<<"I am in getPseudoElecTwoString";
      QString alacant = qgetenv("ALACANT");
      //QString basType(ui.basisElecTwoCombo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      QString pseudoElecTwoType(ui.blpar2Combo->currentText()); // REPLACES THE PIECE OF CODE BELOW
      qDebug()<<"pseudoType"<<pseudoElecTwoType;

      //QString basType;
      //basType=ui.basisElecTwoCombo->itemText(n);

      //QString fullpathfileName;
      //fullpathfileName=alacant+"/BASDAT/"+ui.atomtypeElecTwoCombo->currentText()+"_"+pseudoType+".dat";
      QString pseudoElecTwofileName;
      //pseudoElecTwofileName = alacant+"/PSEUDODAT/"+ui.atomtypeElecTwoCombo->currentText()+"_"+pseudoElecTwoType+".dat";
      QTextStream pseudoElecTwofileStream(&pseudoElecTwofileName);
      pseudoElecTwofileStream << alacant << "/PSEUDODAT/" << m_elementsInElecTwoNr << "_" << pseudoElecTwoType << ".dat";
      qDebug()<<"pseudofileName"<<pseudoElecTwofileName;

      QFileInfo fi(pseudoElecTwofileName);
      //QString comfileName = fi.fileName();
      //qDebug() << "comfileName" << comfileName;
      //QString fileName = fi.baseName();
      //MyClass dataTransmission = new MyClass();
      //------------------------------------------------------------------------------------
      //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
      //------------------------------------------------------------------------------------
      //SimuneAntInputDialog jobname = fileName;
      //------------------------------------------------------------------------------------
      //------------------------------------------------------------------------------------
      qDebug() << "pseudofileName" << pseudoElecTwofileName;
      //QFileInfo::basename().toStdString()

      if (!pseudoElecTwofileName.isEmpty()) {
          //ui.comLineEdit->setText(comfileName);
          //ui.iniLineEdit->setText(fileName + ".ini");
          //ui.savelogLineEdit->setText(fileName + ".log");
          //loadIniFile(fileName + ".ini");
          //loadComFile(comfileName);
          QFile pseudoElecTwoFile(pseudoElecTwofileName);
          if (!pseudoElecTwoFile.open(QFile::ReadOnly | QFile::Text)) {
              QMessageBox::warning(this, tr("Application"),
                                   tr("Cannot read file %1:\n%2.")
                                   .arg(pseudoElecTwofileName)
                                   .arg(pseudoElecTwoFile.errorString()));
              return "";
          }
          QTextStream in(&pseudoElecTwoFile);
      #ifndef QT_NO_CURSOR
          QApplication::setOverrideCursor(Qt::WaitCursor);
      #endif
          QString pseudoElecTwostring = in.readAll();
          pseudoElecTwoFile.close();
      #ifndef QT_NO_CURSOR
          QApplication::restoreOverrideCursor();
      #endif
          qDebug() << "pseudoElecTwostring;";
          qDebug() << pseudoElecTwostring;
          return pseudoElecTwostring;
      }else{
        return "";
      }
  }

  //-----------------------------------------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------------------------------------
  //-----------------------------------------------------------------------------------------------------------------

  void SimuneAntInputDialog::deckDirty(bool dirty)
  {
      qDebug()<<"I am in deckDirty";
    m_dirty = dirty;
    ui.titleLine->setEnabled(!dirty);
    ui.calculationCombo->setEnabled(!dirty);
    ui.theoryCombo->setEnabled(!dirty);
    ui.basisMolecCombo->setEnabled(!dirty);
    ui.multiplicitySpin->setEnabled(!dirty);
    ui.chargeSpin->setEnabled(!dirty);
    ui.procSpin->setEnabled(!dirty);
    ui.outputCombo->setEnabled(!dirty);
    ui.checkpointCheck->setEnabled(!dirty);
    //ui.enableFormButton->setEnabled(dirty);
  }

  void SimuneAntInputDialog::deckIniDirty(bool dirty)
    {
      m_dirty = dirty;
      ui.titleLine->setEnabled(!dirty);
      ui.calculationCombo->setEnabled(!dirty);
      ui.theoryCombo->setEnabled(!dirty);
      ui.basisMolecCombo->setEnabled(!dirty);
      ui.multiplicitySpin->setEnabled(!dirty);
      ui.chargeSpin->setEnabled(!dirty);
      ui.procSpin->setEnabled(!dirty);
      ui.outputCombo->setEnabled(!dirty);
      ui.checkpointCheck->setEnabled(!dirty);
      //ui.enableFormButton->setEnabled(dirty);
    }

  //----------------------------------------------------------------------------------------
  //------------ ADDED BY C. SALGADO -------------------------------------------------------
  //----------------------------------------------------------------------------------------
  void SimuneAntInputDialog::processStarted()
  {
      qDebug() << "processStarted()";
  }

  // conversion start
  //void Dialog::on_startButton_clicked()
  void SimuneAntInputDialog::on_startButton_clicked()
  {
  //---------------------------------------------------------------------

  //---------------------------------------------------------------------

  QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
  env.insert("g09root", "/usr/local"); // Add an environment variable
  env.insert("GAUSS_SCRDIR", "/home/carlos/SCRATCH"); // Add an environment variable
  //export g09root=\"/usr/local\"; export GAUSS_SCRDIR=\"/home/carlos/SCRATCH\"; source $g09root/g09/bsd/g09.login;
  //*mTranscodingProcess.setProcessEnvironment(env);
  mTranscodingProcess->setProcessEnvironment(env);
  //mTranscodingProcess->setStandardInputFile("test0000.com");
  //mTranscodingProcess->setStandardOutputFile("test0000.loga");

  //---------------------------------------------------------------------
  QString program = "./script.sh";

  QStringList arguments;

  QString input = ui.comLineEdit->text();
  //QString input = fileName;
  if(input.isEmpty()) {
    qDebug() << "No input";
    QMessageBox::information(this,
                   tr("launchgaussian"),tr("Input file not specified"));
    return;
  }
  //QString output = ui.savelogLineEdit->text();
  QString output = ui.savelogLineEdit->text();
  if(output.isEmpty()) {
      qDebug() << "No output";
      QMessageBox::information(this,
                   tr("launchgaussian"),tr("Output file not specified"));
      return;
  }

  QString fileName = ui.savelogLineEdit->text();
  qDebug() << "output file check " << fileName;
  qDebug() << "QFile::exists(fileName) = " << QFile::exists(fileName);
  if (QFile::exists(fileName)) {
    if (QMessageBox::question(this, tr("launchgaussian"),
                tr("There already exists a file called %1 in "
                "the current directory. Overwrite?").arg(fileName),
                QMessageBox::Yes|QMessageBox::No, QMessageBox::No)
         == QMessageBox::No)
      return;
    QFile::remove(fileName);
    while(QFile::exists(fileName)) {
           qDebug() << "output file still there";
    }
  }

  //arguments << "-i" << input << output;
  //arguments << input << output;// I will replace this in the next lines.
  QFileInfo fi(input);
  QString inputbaseName = fi.baseName();
  arguments << inputbaseName << output;
  //qDebug() << arguments;
  qDebug() << "arguments are " << arguments;
  //----------------------------------------------------------------------
  mTranscodingProcess->setProcessChannelMode(QProcess::MergedChannels);
  mTranscodingProcess->start(program, arguments);
  //---------------------------------------------------------------------
  if (mTranscodingProcess->waitForStarted(1000) == false)
    qDebug() << "Error starting external program";
  else
    qDebug() << "external program running";
  //---------------------------------------------------------------------

  //qDebug() << "after  mTranscodingProcess" << arguments;
  }

  void SimuneAntInputDialog::readyReadStandardOutput()
    {
        mOutputString.append(mTranscodingProcess->readAllStandardOutput());
        ui.outputlogtextEdit->setText(mOutputString);
        ui.previewlogText->setText(mOutputString);

        // put the slider at the bottom
        ui.outputlogtextEdit->verticalScrollBar()
                ->setSliderPosition(
                    ui.outputlogtextEdit->verticalScrollBar()->maximum());
        ui.previewlogText->verticalScrollBar()
                ->setSliderPosition(
                    ui.previewlogText->verticalScrollBar()->maximum());
    }

  void SimuneAntInputDialog::read_m_process_StandardOutput()
  {
    ui.customstackedWidget->setCurrentIndex(2);
    mOutputString.append(m_process->readAllStandardOutput());
    ui.previewlogText->setText(mOutputString);
    // put the slider at the bottom
    ui.previewlogText->verticalScrollBar()
            ->setSliderPosition(
                ui.previewlogText->verticalScrollBar()->maximum());
  }

  void SimuneAntInputDialog::runningFinished()
  {
    // Set the encoding status by checking output file's existence
    QString fileName = ui.savelogLineEdit->text();
    if (QFile::exists(fileName)) {
        ui.runningStatusLabel
                ->setText("Running Status: Successful!");

        //PrintTransmWid::on_pushButton_clicked();
        //PrintTransmWid.autoPrintTransmission();
        //QString job = MyClass::jobname;
        //QString job = SimuneAntInputDialog::jobname;
        //OpenTransmWidget.auto_Open_triggered(job);
        //-----------------------------------------------------------------------------
        //----------- COMMENTED FOR AVOGADRO ------------------------------------------
        //-----------------------------------------------------------------------------
        //signalFinished();
        //-----------------------------------------------------------------------------
        //-----------------------------------------------------------------------------
           //ui.playOutputButton->setEnabled(true);
    }else {
        ui.runningStatusLabel
                ->setText("Running Status: Failed!");
        //--------------------------------------------------
        // IF GAUSSIAN SCRIPT DOES NOT WRITE OUTPUT, USE THIS.
        //        //QString filename = "Data.txt";
        //        QFile file(fileName);
        //        if (file.open(QIODevice::ReadWrite)) {
        //            QTextStream stream(&file);
        //            //stream << "something" << endl;
        //            stream << mOutputString << endl;
        //            // optional, as QFile destructor will already do it:
        //                file.close();
        //        }
        //--------------------------------------------------
    }
  }

  void SimuneAntInputDialog::on_fileOpenButton_clicked()
  {
    //QString fileName =
    QString fullpathfileName =
        QFileDialog::getOpenFileName(
                this,
                tr("Open File"),
                "C:/TEST",
                //tr("videoss (*.mp4 *.mov *.avi)"));
                //tr("(*.mp4 *.mov *.avi)"));
                tr("(*.com)"));
    QFileInfo fi(fullpathfileName);
    QString comfileName = fi.fileName();
    qDebug() << "comfileName" << comfileName;
    QString fileName = fi.baseName();
    //MyClass dataTransmission = new MyClass();
    //------------------------------------------------------------------------------------
    //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
    //------------------------------------------------------------------------------------
    //SimuneAntInputDialog jobname = fileName;
    //------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------
    qDebug() << "fileName" << fileName;
    //QFileInfo::basename().toStdString()
    if (!fileName.isEmpty()) {
        ui.comLineEdit->setText(comfileName);
        ui.iniLineEdit->setText(fileName + ".ini");
        ui.savelogLineEdit->setText(fileName + ".log");
        loadIniFile(fileName + ".ini");
        loadComFile(comfileName);
    }
  }

  /*
  void SimuneAntInputDialog::on_fileOpenButton_clicked()
  {
    //QString fileName =
    QString fullpathfileName =
        QFileDialog::getOpenFileName(
                this,
                tr("Open File"),
                "C:/TEST",
                //tr("videoss (*.mp4 *.mov *.avi)"));
                //tr("(*.mp4 *.mov *.avi)"));
                tr("(*.com)"));
    QFileInfo fi(fullpathfileName);
    QString comfileName = fi.fileName();
    qDebug() << "comfileName" << comfileName;
    QString fileName = fi.baseName();
    //MyClass dataTransmission = new MyClass();
    //------------------------------------------------------------------------------------
    //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
    //------------------------------------------------------------------------------------
    //SimuneAntInputDialog jobname = fileName;
    //------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------
    qDebug() << "fileName" << fileName;
    //QFileInfo::basename().toStdString()
    if (!fileName.isEmpty()) {
        ui.comLineEdit->setText(comfileName);
        ui.iniLineEdit->setText(fileName + ".ini");
        ui.savelogLineEdit->setText(fileName + ".log");
        loadIniFile(fileName + ".ini");
        loadComFile(comfileName);
    }
  }
  */

  void SimuneAntInputDialog::on_playInputButton_clicked()
    {
        QString program = "C:/FFmpeg/bin/ffplay";
        QStringList arguments;
        QString input = ui.comLineEdit->text();
        QString output = ui.savelogLineEdit->text();
        arguments << input + " " + output;
        mInputPlayProcess->start(program, arguments);
    }

    //void Dialog::on_playOutputButton_clicked()
    void SimuneAntInputDialog::on_playOutputButton_clicked()
    {
        QString program = "C:/FFmpeg/bin/ffplay";
        QStringList arguments;
        QString output = ui.savelogLineEdit->text();
        arguments << output;
        mInputPlayProcess->start(program, arguments);
    }
    void SimuneAntInputDialog::on_antmodeselectbutton1_clicked()
    {
        ui.antmodestackedWidget->setCurrentIndex(0);
    }
    void SimuneAntInputDialog::on_antmodeselectbutton2_clicked()
    {
        ui.antmodestackedWidget->setCurrentIndex(1);
    }

    void SimuneAntInputDialog::on_inputcomButton_clicked()
    {
        ui.customstackedWidget->setCurrentIndex(0);
    }

    void SimuneAntInputDialog::on_inputiniButton_clicked()
    {
        ui.customstackedWidget->setCurrentIndex(1);
    }

    void SimuneAntInputDialog::on_outputlogButton_clicked()
    {
        ui.customstackedWidget->setCurrentIndex(2);
    }

    //void Avogadro::SimuneAntInputDialog::on_previewTextButton_clicked()
    void SimuneAntInputDialog::on_loadedcomButton_clicked()
    {
        ui.loadedstackedWidget->setCurrentIndex(0);
    }

    void SimuneAntInputDialog::on_loadediniButton_clicked()
    {
        ui.loadedstackedWidget->setCurrentIndex(1);
    }

    void SimuneAntInputDialog::on_loadedlogButton_clicked()
    {
        ui.loadedstackedWidget->setCurrentIndex(2);
    }

    void SimuneAntInputDialog::loadComFile(const QString &fileName)
    {
        QFile file(fileName);
        if (!file.open(QFile::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, tr("Application"),
                                 tr("Cannot read file %1:\n%2.")
                                 .arg(fileName)
                                 .arg(file.errorString()));
            return;
        }

        QTextStream in(&file);
    #ifndef QT_NO_CURSOR
        QApplication::setOverrideCursor(Qt::WaitCursor);
    #endif
        QString comstring = in.readAll();
        qDebug() << comstring;
        //ui.inputcomtextEdit->setPlainText(in.readAll());

        ui.inputcomtextEdit->setPlainText(comstring); // For avogadro, I replace this xtline by the next with ui.previewte
        //ui.previewcomText->setPlainText(comstring);

        //ui.inputDeck->setPlainText(comstring);
    #ifndef QT_NO_CURSOR
        QApplication::restoreOverrideCursor();
    #endif

        setCurrentComFile(fileName);
        //statusBar()->showMessage(tr("File loaded"), 2000);
        qDebug() << "File loaded";
    }

    bool SimuneAntInputDialog::saveComFile(const QString &fileName)
    {
        QFile file(fileName);
        if (!file.open(QFile::WriteOnly | QFile::Text)) {
            QMessageBox::warning(this, tr("Application"),
                                 tr("Cannot write file %1:\n%2.")
                                 .arg(fileName)
                                 .arg(file.errorString()));
            return false;
        }

        QTextStream out(&file);
    #ifndef QT_NO_CURSOR
        QApplication::setOverrideCursor(Qt::WaitCursor);
    #endif

        out << ui.inputcomtextEdit->toPlainText();// For avogadro, I replace this xtline by the next with ui.previewte
        //out << ui.previewcomText->toPlainText();

        //out << ui.inputDeck->toPlainText();
    #ifndef QT_NO_CURSOR
        QApplication::restoreOverrideCursor();
    #endif

        setCurrentComFile(fileName);
        //statusBar()->showMessage(tr("File saved"), 2000);
        qDebug() << "File saved";
        return true;
    }

    void SimuneAntInputDialog::setCurrentComFile(const QString &fileName)
    {
        curFile = fileName;
        //curFile = fileName + ".com";

        ui.inputcomtextEdit->document()->setModified(false);// For avogadro, I replace this xtline by the next with ui.previewte
        //ui.previewcomText->document()->setModified(false);

        //ui.inputDeck->document()->setModified(false);
        //setWindowModified(false);

        QString shownName = curFile;
        if (curFile.isEmpty())
            shownName = "untitled.txt";
        //setWindowFilePath(shownName);
    }

    void SimuneAntInputDialog::loadIniFile(const QString &fileName)
    {
        QFile file(fileName);
        if (!file.open(QFile::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, tr("Application"),
                                 tr("Cannot read file %1:\n%2.")
                                 .arg(fileName)
                                 .arg(file.errorString()));
            return;
        }

        QTextStream in(&file);
    #ifndef QT_NO_CURSOR
        QApplication::setOverrideCursor(Qt::WaitCursor);
    #endif
        QString inistring = in.readAll();
        qDebug() << inistring;
        //ui.inputcomtextEdit->setPlainText(in.readAll());
        ui.inputinitextEdit->setPlainText(inistring);
    #ifndef QT_NO_CURSOR
        QApplication::restoreOverrideCursor();
    #endif

        setCurrentIniFile(fileName);
        //statusBar()->showMessage(tr("File loaded"), 2000);
        qDebug() << "File loaded";
    }

    bool SimuneAntInputDialog::saveIniFile(const QString &fileName)
    {
        QFile file(fileName);
        if (!file.open(QFile::WriteOnly | QFile::Text)) {
            QMessageBox::warning(this, tr("Application"),
                                 tr("Cannot write file %1:\n%2.")
                                 .arg(fileName)
                                 .arg(file.errorString()));
            return false;
        }

        QTextStream out(&file);
    #ifndef QT_NO_CURSOR
        QApplication::setOverrideCursor(Qt::WaitCursor);
    #endif

        out << ui.inputcomtextEdit->toPlainText();// For avogadro, I replace this xtline by the next with ui.previewte
        //out << ui.previewiniText->toPlainText();

        //out << ui.inputDeck->toPlainText();
    #ifndef QT_NO_CURSOR
        QApplication::restoreOverrideCursor();
    #endif

        setCurrentIniFile(fileName);
        //statusBar()->showMessage(tr("File saved"), 2000);
        qDebug() << "File saved";
        return true;
    }

    void SimuneAntInputDialog::setCurrentIniFile(const QString &fileName)
    {
        curFile = fileName;
        //curFile = fileName + ".ini";
        ui.inputinitextEdit->document()->setModified(false);
        //setWindowModified(false);

        QString shownName = curFile;
        if (curFile.isEmpty())
            shownName = "untitled.txt";
        //setWindowFilePath(shownName);
    }

    //----------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------
    void Avogadro::QtPlugins::SimuneAntInputDialog::on_antgbrowseButton_clicked()
    {
        //QString fileName =
        QString fullpathfileName =
            QFileDialog::getOpenFileName(
                    this,
                    tr("Open File"),
                    "C:/TEST",
                    //tr("videoss (*.mp4 *.mov *.avi)"));
                    //tr("(*.mp4 *.mov *.avi)"));
                    tr("(*.exe)"));
        QFileInfo fi(fullpathfileName);
        //QString comfileName = fi.fileName();
        QString AntG = fi.absolutePath();
        //QDir AntG = fi.absoluteDir();
        qDebug() << "AntG" << AntG;
        QString exeName = fi.baseName();
        //MyClass dataTransmission = new MyClass();
        //------------------------------------------------------------------------------------
        //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
        //------------------------------------------------------------------------------------
        //SimuneAntInputDialog jobname = fileName;
        //------------------------------------------------------------------------------------
        //------------------------------------------------------------------------------------
        //qDebug() << "fileName" << fileName;
        //QFileInfo::basename().toStdString()
        if (!exeName.isEmpty()) {
            ui.antgbrowseEdit->setText(AntG);
        }
    }



    void SimuneAntInputDialog::on_g09browseButton_clicked()
    {
        QString fullpathfileName =
            QFileDialog::getOpenFileName(
                    this,
                    tr("Open File"),
                    "C:/TEST",
                    //tr("videoss (*.mp4 *.mov *.avi)"));
                    //tr("(*.mp4 *.mov *.avi)"));
                    tr("(*g0*)"));
        QFileInfo fi(fullpathfileName);
        //QString comfileName = fi.fileName();
        QString g09 = fi.absolutePath();
        //QDir AntG = fi.absoluteDir();
        qDebug() << "g09" << g09;
        QString exeName = fi.baseName();
        //MyClass dataTransmission = new MyClass();
        //------------------------------------------------------------------------------------
        //---------------- COMMENTED FOR AVOGADRO --------------------------------------------
        //------------------------------------------------------------------------------------
        //SimuneAntInputDialog jobname = fileName;
        //------------------------------------------------------------------------------------
        //------------------------------------------------------------------------------------
        //qDebug() << "fileName" << fileName;
        //QFileInfo::basename().toStdString()
        QString g09root;
        if(exeName.contains("/g09/g09\n") )
            g09root = exeName.remove("/g09/g09\n");
        else
            if(exeName.contains("/g09/g09") )
                g09root = exeName.remove("/g09/g09");
        if (!g09root.isEmpty()) {
            ui.g09rootbrowseEdit->setText(g09root);
        }
    }

    void SimuneAntInputDialog::on_generateButton_clicked()
    {
        QString fileName = saveAntInputFiles(ui.previewcomText->toPlainText(), ui.previewiniText->toPlainText(),
                              tr("ANT.G Input Deck"), QString("com"), QString("ini"));
        if (fileName.isEmpty())
          return;
    }


    void SimuneAntInputDialog::on_natomel1Spin_editingFinished()
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_natomel2Spin_editingFinished()
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_nembed1Spin_editingFinished()
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_nembed2Spin_editingFinished()
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_type1Combo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_type2Combo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_blpar1Combo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_blpar2Combo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_atomtypeMolecCombo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

    void SimuneAntInputDialog::on_basisMolecCombo_currentIndexChanged(const QString &arg1)
    {
        updatePreviewComText();
    }

} // end namespace QtPlugins
} // end namespace Avogadro


