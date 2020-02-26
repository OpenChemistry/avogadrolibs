/**********************************************************************
  SimuneAntInputDialog - Dialog for generating Gaussian input decks

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

#ifndef SIMUNEANTINPUTDIALOG_H
#define SIMUNEANTINPUTDIALOG_H

#include <QProcess>
#include <QProgressDialog>

#include <QtCore/QSettings>

//#include "inputdialog.h"
#include "simuneantinput.h"
#include "ui_simuneantinputdialog.h"

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
class SimuneAntHighlighter;

  //class Molecule;
  //class SimuneAntInputDialog : public InputDialog
class SimuneAntInputDialog : public QDialog
{
  Q_OBJECT
 public:
  //explicit SimuneAntInputDialog(QWidget *parent = 0, Qt::WindowFlags f = 0 );
  explicit SimuneAntInputDialog(QWidget *parent_ = 0, Qt::WindowFlags f = 0 );
  ~SimuneAntInputDialog();
  void setMolecule(QtGui::Molecule *molecule);
  enum calculationType{SP, OPT, FREQ};
  //enum theoryType{AM1, PM3, RHF, B3LYP, MP2, CCSD};
  enum theoryType{lsda,bpbe,blyp, B3LYP,hseh1pbe};
  enum basisType{minimal6s, CRENBS, LANL2DZ,STO3G, B321G, B631Gd, B631Gdp};
  enum coordType{CARTESIAN, ZMATRIX, ZMATRIX_COMPACT};
  //---------------------------------------------------------------------------------------
  // I ADD NEW VARIABLES FOR THE ANT.G .INI INPUT FILE ALSO STARTED WITH m_*.
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
  QString pathToGaussian() const;
 signals:
   /**
    * Emitted when the user requests that a job's output be loaded in Avogadro2.
    */
  void openJobOutput(const MoleQueue::JobObject &job); // SPECIFIC SIGNAL OF AVOGADRO2.
Q_SIGNALS: // SPECIFIC SIGNAL COPIED FROM AVOGADRO1.

  void readOutput(const QString outputFileName); // SPECIFIC SIGNAL COPIED FROM AVOGADRO1.

protected:
  /**
  * Reimplemented to update the dialog when it is shown
  */
  void showEvent(QShowEvent *event);
  QString saveInputFile(QString inputDeck, QString fileType, QString ext);
  QString saveAntInputFiles(QString inputDeck,QString inputiniDeck, QString fileType, QString ext, QString iniext);
  QString saveAntComFile(QString inputDeck, QString fileType, QString ext);
  QString saveAntIniFile(QString inputDeck, QString fileType, QString ext);
private:
  Ui::SimuneAntInputDialog ui;

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
  bool m_useAntG = true;
  bool m_l101 = true;
  bool m_l103 = true;
  bool m_l502 = true;
  bool m_l703 = false;
  coordType m_coordType;
  bool m_dirty;
  bool m_warned;
  QProcess *m_process;
  QProgressDialog *m_progress;
  QString m_inputFile;

  //---------------------------------------------------------------------------------------
  // I ADD NEW VARIABLES FOR THE ANT.G .INI INPUT FILE ALSO STARTED WITH m_*.
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

  //---------------------------------------------------------------------------------------

  // Generate an input deck as a string
  QString generateInputDeck();
  QString generateInputIniDeck();
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

  // Enable/disable form elements
  void deckDirty(bool);
  void deckIniDirty(bool);
  //---------------------------------------------------------------------------------------
  //Ui::Dialog *ui;
  //Ui::DiaWidget *ui;
  QProcess *mTranscodingProcess;
  QProcess *mInputPlayProcess;
  QProcess *mOutputPlayProcess;
  QString mOutputString;
  QString curFile;
  //---------------------------------------------------------------------------------------
  //SimuneAntHighlighter *m_highlighter; // COPIED FROM GAMESSINPUTDIALOG
  SimuneAntHighlighter *m_highlighter; // COPIED FROM GAMESSINPUTDIALOG
  bool m_updatePending; // COPIED FROM GAMESSINPUTDIALOG
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
private Q_SLOTS:
  //! Button Slots
  void resetClicked();
  void generateClicked();
  void saveAntComClicked();
  void saveAntIniClicked();
  void computeClicked();
  void computeClickedAnt();
  void enableFormClicked();
  void moreClicked();
  void previewEdited();
  void previewIniEdited();
  void getTitle();
  void setCalculation(int);
  void setTheory(int);
  void setBasis(int);
  void setMolecBasis(int);
  void setMultiplicity(int);
  void setCharge(int);
  void setProcs(int);
  void setOutput(int);
  void setChk(int);
  void setUseAntG(int);
  void setUseAntGl101(int);
  void setUseAntGl103(int);
  void setUseAntGl502(int);
  void setUseAntGl703(int);
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

  void updateTitlePlaceholder();
  void updateTitle();
  //----------------------------------------------

  void connectBasic();
  void connectPreview();
  void connectButtons();
  void connectIni();

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

  QString generateJobTitle() const;

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

  void on_antmodeselectbutton1_clicked();

  void on_antmodeselectbutton2_clicked();

  void on_antgbrowseButton_clicked();

  //---------------------------------------------------------------------------------------

  //------------------------------------------------------------------------------
  //----------- END OF CODE FROM AVOGADRO2 ---------------------------------------
  //------------------------------------------------------------------------------

  void on_g09browseButton_clicked();

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

protected:
  //QString saveInputFile(QString inputDeck, QString fileType, QString ext);

  QtGui::Molecule *m_molecule; // COPIED FROM COORDINATEEDITOR.CPP IN NEW AVOGADRO2 BUT TO MATCH m_molecule()->atoms() PROPERTY FROM OLD AVOGADRO-QT4.
  //QtGui::Molecule* m_molecule;
  QString m_title;
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
