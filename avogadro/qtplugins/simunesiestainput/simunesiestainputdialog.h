/**********************************************************************
  SimuneSiestaInputDialog - Dialog for generating Gaussian input decks

  Copyright (C) 2008-2009 Marcus D. Hanwell
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

#ifndef SIMUNESIESTAINPUTDIALOG_H
#define SIMUNESIESTAINPUTDIALOG_H

#include <QProcess>
#include <QProgressDialog>

#include <QtCore/QSettings>

#include <QWidget>
#include <QFile>
#include <QFileDialog>
#include <QTextStream>
#include <QDebug>
#include <QString>
#include <QStandardItemModel>
#include <QVector>
#include <QVector3D>
#include <QList>

//#include "myclass.h"
#include <iostream>
#include <string>

//#include "inputdialog.h"
#include "simunesiestainput.h"
#include "ui_simunesiestainputdialog.h"

class QJsonObject;

namespace MoleQueue {
class JobObject;
}

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
//class GamessHighlighter;
class SimuneSiestaHighlighter;

  //class Molecule;
  //class SimuneSiestaInputDialog : public InputDialog
class SimuneSiestaInputDialog : public QDialog
{
  Q_OBJECT
 public:
  //explicit SimuneSiestaInputDialog(QWidget *parent = 0, Qt::WindowFlags f = 0 );
  explicit SimuneSiestaInputDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
  ~SimuneSiestaInputDialog();
  void setMolecule(QtGui::Molecule *molecule);
  enum calculationType{SP, OPT, FREQ};
  //enum theoryType{AM1, PM3, RHF, B3LYP, MP2, CCSD};
  enum theoryType{lsda,bpbe,blyp, B3LYP,hseh1pbe};
  enum basisType{minimal6s, CRENBS, LANL2DZ,STO3G, B321G, B631Gd, B631Gdp};
  enum coordType{CARTESIAN, ZMATRIX, ZMATRIX_COMPACT};
  enum AtomicCoordinatesFormatCombo{ScaledCartesian,Ang,ScaledByLatticeVectors,ZMatrix,ZMatrix_Compact};
  // SIESTA .FDF
  enum BasisSiesta{SZ};
  enum XCFunctional{LDA,GGA,VDW};
  enum XCAuthors{CA};
  enum SolutionMethod{diagon};
  enum BandLinesScale{ReciprocalLatticeVectors};
  enum MDTypeOfRun{cg};
  // END SIESTA .FDF
  //---------------------------------------------------------------------------------------
  // I ADD NEW VARIABLES FOR THE SIESTA .INI INPUT FILE ALSO STARTED WITH m_*.
  enum typeBetheCombo{BETHE, GRAPHENE, ONEDLEAD, GHOST};
  //enum type2Combo{BETHE, GRAPHENE, ONEDLEAD, GHOST};
  enum blparCombo{lsdacrenbs, lsda6s, papacon, papaconsd, papaconold};
  //enum blpar2Combo{lsdacrenbs, lsda6s, papacon, papaconsd, papaconold};
  enum optAccuracyCombo{loose,tight,verytight};
  //---------------------------------------------------------------------------------------

  /**
   * Save the settings for this extension.
   * @param settings Settings variable to write settings to.
   */
  virtual void writeSettings(QSettings &settings) const;
   /**
   * Read the settings for this extension.
   * @param settings Settings variable to read settings from.
   */
  virtual void readSettings(QSettings &settings);
  QString pathToG03() const;
  QString pathToG09() const;
  QString pathToSIESTA_old() const;
  QString pathToSiesta() const;
  QString pathToGaussian() const;

  void appendPseudosToSubmitJob(MoleQueue::JobObject &job);


 signals:
   /**
    * Emitted when the user requests that a job's output be loaded in Avogadro2.
    */
  void openJobOutput(const MoleQueue::JobObject &job); // SPECIFIC SIGNAL OF AVOGADRO2.
  void updateFdfSignal();
Q_SIGNALS: // SPECIFIC SIGNAL COPIED FROM AVOGADRO1.

  void readOutput(const QString outputFileName); // SPECIFIC SIGNAL COPIED FROM AVOGADRO1.

protected:
  /**
  * Reimplemented to update the dialog when it is shown
  */
  void showEvent(QShowEvent *event);
  QString saveInputFile(QString inputDeck, QString fileType, QString ext);
  QString saveSiestaInputFiles(QString inputDeck,QString inputiniDeck, QString fileType, QString ext, QString iniext);
  QString saveSiestaInputFile(QString inputDeck, QString fileType, QString ext);
  QString saveSiestaComFile(QString inputDeck, QString fileType, QString ext);
  QString saveSiestaIniFile(QString inputDeck, QString fileType, QString ext);
private:
  Ui::SimuneSiestaInputDialog ui;

  // Internal data structure for the calculation
  //   QString m_title;
  calculationType m_calculationType;
  theoryType m_theoryType = lsda;
  basisType m_basisType = minimal6s;
  // int m_multiplicity;
  // int m_charge;
  int m_procs;
  QString m_output;
  bool m_chk;
  bool m_useSiestaG = true;
  bool m_l101 = true;
  bool m_l103 = true;
  bool m_l502 = true;
  bool m_l703 = false;
  coordType m_coordType;
  AtomicCoordinatesFormatCombo m_AtomicCoordinatesFormat = Ang;
  bool m_dirty;
  bool m_fdfdirty;
  bool m_warned;
  bool m_fdfwarned;
  QProcess *m_process;
  QProgressDialog *m_progress;
  QString m_inputFile;

  //---------------------------------------------------------------------------------------
  // I ADD NEW VARIABLES FOR THE SIESTA .INI INPUT FILE ALSO STARTED WITH m_*.
  bool m_hamiltonCheck = true;
  bool m_mullikenCheck = true;
  bool m_leaddosCheck = true;
  bool m_htransmCheck = false;

  typeBetheCombo m_type1Combo = BETHE;
  typeBetheCombo m_type2Combo = BETHE;
  blparCombo m_blpar1Combo = lsda6s;
  blparCombo m_blpar2Combo = lsda6s;

  int m_natomel1Spin = 0;
  int m_natomel2Spin = 0;
  int m_nembed1Spin = 0;
  int m_nembed2Spin = 0;
  int m_nspinlockSpin = 0;
  int m_nalphaSpin = 0;
  int m_nbetaSpin = 0;
  int m_nchannelsSpin = 0;
  int m_ldosbegSpin = 0;
  int m_ldosendSpin = 0;
  int m_rtmbegSpin = 0;
  int m_rtmendSpin = 0;

  int m_paccSpin = -1.0;
  int m_chargeaccSpin = -1.0;
  int m_fermiaccSpin = -1.0;
  int m_selfaccSpin = -1.0;
  int m_etaSpin = 6;
  int m_slSpin = -1.0;
  //int m_ssmSpin = -1.0;
  int m_swoffsplSpin = -1.0;


  double m_alphaSpin = -1.0;
  double m_overlapSpin = -1.0;
  double m_biasvoltSpin = 0.0;
  double m_qexcessSpin = 0.0;
  double m_fermistartSpin = 9999.0;
  double m_estepSpin = 2;
  double m_ew1Spin = 0.0;
  double m_ew2Spin = 0.0;

  int m_scfConver = 6;
  int m_scfMaxCycle = 300;

  bool m_scfnosymm = true;
  bool m_scfnodamp = true;
  bool m_scfnovaracc = true;

  bool m_globalnosymm = true;

  int m_optmaxcycles = 8;

  optAccuracyCombo m_optAccuracy = loose;

  bool m_opt = false;
  bool m_force = false;
  bool m_UHF = true;

  //QVector<QString> m_elementsInMolecStr;
  QVector<int> m_elementsInMolecNr;
  QVector<int> m_firstAtominElement;
  QVector<int> m_lastAtominElement;

  int m_elementsInElecOneNr;
  //QString m_elementsInElecOneStr;
  int m_elementsInElecTwoNr;
  //QString m_elementsInElecTwoStr;

  // SIESTA .FDF
  XCFunctional m_XCFunctional = LDA;
  XCAuthors m_XCAuthors = CA;
  SolutionMethod m_SolutionMethod = diagon;
  BandLinesScale m_BandLinesScale = ReciprocalLatticeVectors;
  MDTypeOfRun m_MDTypeOfRun = cg;

  // END SIESTA

  //---------------------------------------------------------------------------------------

  // Generate an input deck as a string
  QString generateInputDeck();
  QString generateInputIniDeck();
  QString generateInputFdfDeck();
  // Translate enums to strings
  QString getCalculationType(calculationType t);
  QString getTheoryType(theoryType t);
  QString getBasisType(basisType t);

  QString getoptAccuracy(optAccuracyCombo t);

  void updateMolecBasisInput();

  //QString getLoadFullBasisType(basisType t);
  void getLoadFullBasisTypeOld(int);
  void getLoadFullBasisType(int);
  QString getBasisMolecString();
  QString getBasisElecOneString();
  QString getBasisElecTwoString();
  void getLoadFullPseudoType(int);
  QString getPseudoMolecString();
  QString getPseudoElecOneString();
  QString getPseudoElecTwoString();

  //------------------------------------------------------------------
  QString getBetheType(typeBetheCombo t);
  QString getBlpar(blparCombo t);
  QString getoptAccuracy(blparCombo t);
  //------------------------------------------------------------------

  // END SIESTA .FDF
  QString getBasisSiesta(BasisSiesta t);
  QString getXCFunctional(XCFunctional t);
  QString getXCAuthors(XCAuthors t);
  QString getSolutionMethod(SolutionMethod t);
  QString getBandLinesScale(BandLinesScale t);

  QString getMDTypeOfRun(MDTypeOfRun t);
  QString getSpinPolarized();

  QString getBandsBlock();
  QString getLatticeVectorsBlock();
  void getLatticeVectors();

  void modelBrillouinCreate();
  //void modelBrillouinAddNewRow();
  int modcheckStringBandsBrillouin(QString &temp, QChar character);

  // END SIESTA .FDF

  // Enable/disable form elements
  void deckDirty(bool);
  void deckIniDirty(bool);
  void deckFdfDirty(bool);
  //---------------------------------------------------------------------------------------
  //Ui::Dialog *ui;
  //Ui::DiaWidget *ui;
  QProcess *mTranscodingProcess;
  QProcess *mInputPlayProcess;
  QProcess *mOutputPlayProcess;
  QString mOutputString;
  QString curFile;
  //---------------------------------------------------------------------------------------
  //SimuneSiestaHighlighter *m_highlighter; // COPIED FROM GAMESSINPUTDIALOG
  SimuneSiestaHighlighter *m_highlighter; // COPIED FROM GAMESSINPUTDIALOG
  bool m_updatePending; // COPIED FROM GAMESSINPUTDIALOG
  bool m_fdfupdatePending;
  QMap<QComboBox *, int> m_optionCache; // COPIED FROM GAMESSINPUTDIALOG

  // VALIDATESTORAGE COPIED FROM COORDINATEEDITOR.CPP IN NEW AVOGADRO2 BUT TO MATCH m_molecule()->atoms() PROPERTY FROM OLD AVOGADRO-QT4.
  // State storage for validateInput methods. PIMPL'd for organization.
  class ValidateStorage;
  ValidateStorage *m_validate;

//  Q_SIGNALS:
//    void readOutput(const QString outputFileName);

public Q_SLOTS:
  void updatePreviewText();
  void updatePreviewComText();
  void updatePreviewIniText();
  void updatePreviewFdfText();
  void initPreviewFdfText();
private Q_SLOTS:
  //! Button Slots
  void resetClicked();
  void generateClicked();
  void saveSiestaComClicked();
  void saveSiestaIniClicked();
  void computeClicked();
  void computeClickedSiesta();
  void enableFormClicked();
  void moreClicked();
  void previewEdited();
  void previewIniEdited();
  void previewFdfEdited();
  void getTitle();
  void getFdfSystemName();
  void setCalculation(int);
  void setTheory(int);
  void setBasis(int);
  void setMolecBasis(int);
  void setMultiplicity(int);
  void setCharge(int);
  void setProcs(int);
  void setOutput(int);
  void setChk(int);
  void setUseSiestaG(int);
  void setUseSiestaGl101(int);
  void setUseSiestaGl103(int);
  void setUseSiestaGl502(int);
  void setUseSiestaGl703(int);
  void setCoords(int);

  void setUHF(int);
  void setglobalnosymm(int);
  void setscfMaxCycle(int);
  void setscfnosymm(int);
  void setscfnodamp(int);
  void setscfnovaracc(int);
  void setoptmaxcycles(int);
  void setoptAccuracy(int);
  void setOpt(int);
  void setForce(int);

  //---------------------------------------------------------------------------------------------
  void sethamiltonCheck(int);
  void setmullikenCheck(int);
  void setleaddosCheck(int);
  void sethtransmCheck(int);
  void settype1Combo(int);
  void settype2Combo(int);
  void setblpar1Combo(int);
  void setblpar2Combo(int);
  void setnatomel1Spin(int);
  void setnatomel2Spin(int);
  void setnembed1Spin(int);
  void setnembed2Spin(int);
  void setnspinlockSpin(int);
  void setnalphaSpin(int);
  void setnbetaSpin(int);
  void setnchannelsSpin(int);
  void setldosbegSpin(int);
  void setldosendSpin(int);
  void setrtmbegSpin(int);
  void setrtmendSpin(int);
  void setpaccSpin(int);
  void setchargeaccSpin(int);
  void setfermiaccSpin(int);
  void setselfaccSpin(int);
  void setetaSpin(int);
  void setslSpin(int);
  //void setssmSpin(int);
  void setswoffsplSpin(int);

  void setalphaSpin(double);
  void setoverlapSpin(double);
  void setbiasvoltSpin(double);
  void setqexcessSpin(double);
  void setfermistartSpin(double);
  void setestepSpin(double);
  void setew1Spin(double);
  void setew2Spin(double);

  void setscfConver(int);


  // SIESTA .FDF

  void setBasisSiestaCombo(int n);
  void setXCFunctionalCombo(int n);
  void setXCAuthorsCombo(int n);
  void setMDTypeOfRunCombo(int n);
  void setSolutionMethodCombo(int n);
  void setBandLinesScaleCombo(int n);
  void setAtomicCoordinatesFormatCombo(int);
  void setSpinPolarized(int n);

  void setKGridCutoffSpin(double n);
  void setMeshCutoffSpin(double n);
  void setMixingWeightSpin(double n);
  void setDMTolerance(double n);
  void setElectronicTemperature(double n);
  void setdmNumberPulay(int n);
  void setWriteMullikenPopSpin(int n);

  void setWriteCoorInitialCheck(int n);
  void setWriteCoorStepCheck(int n);
  void setWriteForcesCheck(int n);
  void setWriteKpointsCheck(int n);
  void setWriteEigenvaluesCheck(int n);
  void setWriteKbandsCheck(int n);
  void setWriteBandsCheck(int n);
  void setWriteCoorXmolCheck(int n);
  void setWriteMDCoorXmolCheck(int n);
  void setWriteMDhistoryCheck(int n);
  void setDMUseSaveDMCheck(int n);
  void setMDUseSaveXVCheck(int n);
  void setMDUseSaveCGCheck(int n);
  void setSaveRhoCheck(int n);
  void setSaveDeltaRhoCheck(int n);
  void setSaveElectrostaticPotentialCheck(int n);
  void setSaveTotalPotentialCheck(int n);
  void setWriteSiestaDimCheck(int n);
  void setWriteDencharCheck(int n);
  void setWriteLatticeVectorsCheck(int n);


  void copyPseudosToWorkingDirectory(QString targetDirectory);

  void setLatticeConstantSpin(double n);

  void setLatticeVectorA1xSpin(double n);
  void setLatticeVectorA1ySpin(double n);
  void setLatticeVectorA1zSpin(double n);

  void setLatticeVectorA2xSpin(double n);
  void setLatticeVectorA2ySpin(double n);
  void setLatticeVectorA2zSpin(double n);

  void setLatticeVectorA3xSpin(double n);
  void setLatticeVectorA3ySpin(double n);
  void setLatticeVectorA3zSpin(double n);
  // END SIESTA .FDF

  //---------------------------------------------------------------------------------------------
  void finished(int);
  void stopProcess();
  void on_loadedcomButton_clicked();
  void on_loadediniButton_clicked();
  void on_loadedlogButton_clicked();
  //------------------------------------------------------------------------------
  //---------- BEGIN OF CODE FROM AVOGADRO2 --------------------------------------
  //------------------------------------------------------------------------------
  //----- PRIVATE SLOTS --------------------------
  void defaultsClicked();
  void submitClicked();
  void submitClickedSiesta();

  void updateTitlePlaceholder();
  void updateTitle();

  void updateFdfSystemName();
  void updateFdfSystemNamePlaceholder();
  //----------------------------------------------

  void connectBasic();
  void connectPreview();
  void connectButtons();
  void connectIni();
  void connectFdf();

  //void buildOptions();
  void updateOptionCache();
  void restoreOptionCache();
  //void buildCalculateOptions();
  //void buildTheoryOptions();
  //void buildBasisOptions();
  //void buildStateOptions();
  //void buildMultiplicityOptions();
  //void buildChargeOptions();

  void setBasicDefaults();
  void setIniDefaults();
  void setFdfDefaults();

  QString generateJobTitle() const;

  void storeAtomsToValidate();

  // START .FDF

  QString generateJobFdfSystemName() const;
  int getNumberOfSpecies();
  QString getChemicalSpeciesLabel();
  QString getAtomicCoordinatesAndAtomicSpeciesUnscaled();
  QString getAtomicCoordinatesAndAtomicSpeciesScaledByLatticeVectors();
  void updateReciprocalLattice();

  void updateMoleculeCoordinates();
  void storeCoordinates();
  void storeCoordinatesFromValidateToUnscaled();
  //void storeCoordinatesScaledByLatticeVectors();
  void storeCoordinatesFromUnscaledToScaledByLatticeVectors();
  void storeCoordinatesFromScaledByLatticeVectorsToUnscaled();
  QVector<QVector3D> matrix3DInverse(QVector<QVector3D> m);
  QVector3D matrix3DByVector3D(QVector<QVector3D> m, QVector3D v);

  void modelCoordinatesUnscaledCreate();
  void modelCoordinatesScaledByLatticeVectorsCreate();

  // END .FDF

  void on_startButton_clicked();
  void readyReadStandardOutput();
  void read_m_process_StandardOutput();

  void processStarted();
  void runningFinished();
  void on_fileOpenButton_clicked();
  void on_playInputButton_clicked();
  void on_playOutputButton_clicked();
  void loadComFile(const QString &fileName);
  bool saveComFile(const QString &fileName);
  void setCurrentComFile(const QString &fileName);
  void loadIniFile(const QString &fileName);
  bool saveIniFile(const QString &fileName);
  void setCurrentIniFile(const QString &fileName);
  //void yourSlot();

  void on_inputcomButton_clicked();

  void on_inputiniButton_clicked();

  void on_outputlogButton_clicked();

  void on_inputFdfButton_clicked();

  void on_antmodeselectbutton1_clicked();

  void on_antmodeselectbutton2_clicked();

  void on_antgbrowseButton_clicked();

  //---------------------------------------------------------------------------------------

  //------------------------------------------------------------------------------
  //----------- END OF CODE FROM AVOGADRO2 ---------------------------------------
  //------------------------------------------------------------------------------

  void on_siestabrowseButton_clicked();

  void on_generateButton_clicked();
/*
  void on_basisMolecCombo_currentIndexChanged(const QString &arg1);
*/
//  void on_basisMolecCombo_currentIndexChanged(int index);


  void on_setAutoBasisButton_clicked();
  void on_setBasisButton_clicked();

  void on_natomel1Spin_editingFinished();
  void on_natomel2Spin_editingFinished();
  void on_nembed1Spin_editingFinished();
  void on_nembed2Spin_editingFinished();

  void on_type1Combo_currentIndexChanged(const QString &arg1);
  void on_type2Combo_currentIndexChanged(const QString &arg1);
  void on_blpar1Combo_currentIndexChanged(const QString &arg1);
  void on_blpar2Combo_currentIndexChanged(const QString &arg1);

  void on_basisMolecCombo_currentIndexChanged(const QString &arg1);
  void on_atomtypeMolecCombo_currentIndexChanged(const QString &arg1);

  void on_BrillouinAddNewButton_clicked();
  void on_BrillouinModel_changed();
  void on_BrillouinDeleteLastButton_clicked();
  void on_updateLatticeVectorsToFdfButton_clicked();

  void on_CoordinatesAddNewButton_clicked();
  void on_CoordinatesUnscaledModel_changed();
  void on_CoordinatesScaledByLatticeVectorsModel_changed();
  void on_CoordinatesDeleteLastButton_clicked();
  void on_updateCoordinatesToFdfButton_clicked();
  void on_updateCoordinatesUnscaledToMoleculeButton_clicked();


protected:
  //QString saveInputFile(QString inputDeck, QString fileType, QString ext);

  QtGui::Molecule *m_molecule; // COPIED FROM COORDINATEEDITOR.CPP IN NEW AVOGADRO2 BUT TO MATCH m_molecule()->atoms() PROPERTY FROM OLD AVOGADRO-QT4.
  //QtGui::Molecule* m_molecule;
  QString m_title;

  // SIESTA .FDF

  QStandardItemModel *modelBrillouin;
  QStandardItemModel *modelBrillouinLabels;
  QList<QStandardItem*> standardItemListBrillouin;
  QList<QStandardItem*> standardItemListBrillouinLabels;
  int brillouinitemcount = 0;

  QVector<QVector<double> > brillouinCoord;
  QStringList brillouinLabels;
  QVector<int> brillouinNPoints;


  QString m_SystemName;
  QString m_SystemLabel;
  QList<QString> m_Species;
  QList<int> m_SpeciesAtomicNumber;
  QList<int> m_SpeciesIntegerLabel;

  BasisSiesta m_BasisSiesta = SZ;

  QStandardItemModel *modelCoordinatesUnscaled;
  //QStandardItemModel *modelCoordinatesUnscaledLabels; // replaced by m_Species;
  QList<QStandardItem*> standardItemListCoordinatesUnscaled;
  QList<QStandardItem*> standardItemListCoordinatesUnscaledLabels;

  QStandardItemModel *modelCoordinatesScaledByLatticeVectors;
  //QStandardItemModel *modelCoordinatesScaledByLatticeVectorsLabels; // replaced by m_Species;
  QList<QStandardItem*> standardItemListCoordinatesScaledByLatticeVectors;
  QList<QStandardItem*> standardItemListCoordinatesScaledByLatticeVectorsLabels;

  QVector<QVector3D> CoordinatesUnscaled;
  QVector<QVector3D> CoordinatesScaledByLatticeVectors;

  double m_LatticeConstant = 1.0;
  double m_ReciprocalLatticeConstant = 1.0;
  QVector3D LatticeVectorA1;
  QVector3D LatticeVectorA2;
  QVector3D LatticeVectorA3;
  QVector3D ReciprocalLatticeVectorB1;
  QVector3D ReciprocalLatticeVectorB2;
  QVector3D ReciprocalLatticeVectorB3;

  double m_KGridCutoff = 7.0;
  bool m_SpinPolarized = false;
  double m_MeshCutoff = 200.0;
  double m_DMMixingWeight = 0.3;
  int m_DMTolerance = 4;
  int m_DMNumberPulay = 3;
  double m_ElectronicTemperature = 5;

  bool m_WriteCoorInitial = false;
  bool m_WriteCoorStep = false;
  bool m_WriteForces = false;
  bool m_WriteKpoints = false;
  bool m_WriteEigenvalues = false;
  bool m_WriteKbands = false;
  bool m_WriteBands = true;
  bool m_WriteMullikenPop = false;
  bool m_WriteCoorXmol = false;
  bool m_WriteMDCoorXmol = false;
  bool m_WriteMDhistory = false;
  bool m_DMUseSaveDM = false;
  bool m_MDUseSaveXV = false;
  bool m_MDUseSaveCG = false;
  bool m_SaveRho = false;
  bool m_DeltaRho = false;
  bool m_SaveDeltaRho = false;
  bool m_SaveElectrostaticPotential = false;
  bool m_SaveTotalPotential = false;
  bool m_WriteSiestaDim = false;
  bool m_WriteDenchar = false;
  bool m_WriteLatticeVectors = false;

  // END SIESTA .FDF

  int m_multiplicity;
  int m_charge;
  //QString m_fileName;
  QString m_savePath;

  //QVector<QString> m_basisTotalText;
  QString m_basisTotalText;
  //QTextStream m_basisTotalText;
  QString m_pseudoTotalText;
};
} // end namespace QtPlugins
} // end namespace Avogadro

#endif
