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

#ifndef OPENMMINPUTDIALOG_H
#define OPENMMINPUTDIALOG_H

#include "ui_openmminputdialog.h"

#include <QHash>
#include <QtCore/QSettings>

class QJsonObject;
class QTextEdit;

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
class OpenMMInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit OpenMMInputDialog(QWidget* parent = nullptr,
                             Qt::WindowFlags flag = 0);
  ~OpenMMInputDialog();

  void readSettings(QSettings&);
  void writeSettings(QSettings&) const;

  enum forceFieldType
  {
    amber96,
    amber99sb,
    amber99sbildn,
    amber99sbnmr,
    amber03,
    amber10
  };
  enum waterModelType
  {
    spce,
    tip3p,
    tip4pew,
    tip5p,
    implicit
  };
  enum nonBondedType
  {
    NoCutoff,
    CutoffNonPeriodic,
    CutoffPeriodic,
    Ewald,
    PME
  };
  enum constraintType
  {
    None,
    HBonds,
    AllBonds,
    HAngles
  };
  enum integratorType
  {
    Langevin,
    Verlet,
    Brownian,
    VariableLangevin,
    VariableVerlet
  };
  enum barostatType
  {
    NoBarostat,
    MonteCarlo
  };
  enum platformType
  {
    Reference,
    OpenCL,
    CPU,
    CUDA
  };
  enum precisionType
  {
    singlePrecision,
    mixedPrecision,
    doublePrecision
  };
  void setMolecule(QtGui::Molecule* molecule);

protected:
  /**
   * Reimplemented to update the dialog when it is shown
   */
  void showEvent(QShowEvent* event);

private:
  Ui::OpenMMInputDialog ui;
  QtGui::Molecule* m_molecule;

  // QString m_title;
  QString m_readData;
  forceFieldType m_forceFieldType;
  QString m_title;
  QString m_savePath;
  waterModelType m_waterModelType;
  nonBondedType m_nonBondedType;
  constraintType m_constraintType;
  integratorType m_integratorType;
  barostatType m_barostatType;

  int m_deviceIndex;
  int m_openclPlatformIndex;
  int m_rigidWater;
  double m_temperature;
  double m_generationTemperature;
  double m_nonBondedCutoff;
  double m_timeStep;
  double m_ewaldTolerance;
  double m_constraintTolerance;
  int m_reportInterval;
  int m_equilibriationSteps;
  int m_productionSteps;
  double m_errorTolerance;
  double m_collisionRate;
  double m_pressure;
  int m_barostatInterval;
  QString m_dumpXYZ;
  int m_dumpStep;
  int m_velocityDistRandom;
  platformType m_platformType;
  precisionType m_precisionType;
  int m_thermoInterval;
  int m_minimize;
  int m_minimizeSteps;
  bool m_DCDReporter;
  bool m_PDBReporter;
  bool m_stateDataReporter;
  bool m_stepIndex;
  bool m_time;
  bool m_speed;
  bool m_progress;
  bool m_potentialEnergy;
  bool m_kineticEnergy;
  bool m_totalEnergy;
  bool m_temperatureCheck;
  bool m_volume;
  bool m_density;

  QString m_output;
  bool m_dirty;
  bool m_warned;
  bool readData;

  QTextEdit* m_jobEdit;
  QTextEdit* m_moleculeEdit;
  QString m_inputCoordFileName;
  QString m_topologyFileName;
  QString m_jobFileName;

  // Generate an input deck as a string
  QString generateInputDeck();
  // Translate enums to strings
  QString getForceFieldType(forceFieldType t);
  QString getImplicitSolventType(forceFieldType t);
  QString getConstraintType(constraintType t);
  QString getWaterModelType(waterModelType t);
  QString getNonBondedType(nonBondedType t);
  QString getIntegratorType(integratorType t);
  QString getBarostatType(barostatType t);
  QString getRigidWater(int t);
  QString getVelocityDistRandom(int t);
  QString getPlatformType(platformType t);
  QString getPrecisionType(precisionType t);
  QString getMinimize(int t);

  // Enable/disable form elements
  void deckDirty(bool);
  void addMoleculeDataTab();

public Q_SLOTS:
  void updatePreviewText();

private Q_SLOTS:
  //! Button Slots
  void textEditModified();
  void resetClicked();
  void generateClicked();
  void enableFormClicked();

  void setScriptName();
  void setInputCoordName();
  void setTopologyName();

  void setForceField(int);
  void setConstraintType(int);
  void setWaterModelType(int);
  void setNonBondedType(int);

  void setIntegratorType(int);
  void setBarostatType(int);

  void setRigidWater(int);
  void setTemperature(double);
  void setGenerationTemperature(double);
  void setNonBondedCutoff(double);

  void setTimeStep(double);
  void setEwaldTolerance(double);
  void setConstraintTolerance(double);
  void setReportInterval(int);
  void setEquilibriationSteps(int);
  void setProductionSteps(int);
  void setDeviceIndex(int);
  void setOpenCLPlatformIndex(int);
  void setErrorTolerance(double);
  void setCollisionRate(double);
  void setPressure(double);
  void setBarostatInterval(int);

  void setVelocityDistRandom(int);
  void setDCDReporter(bool);
  void setPDBReporter(bool);
  void setStateDataReporter(bool);
  void setStepIndexBoolean(bool);
  void setTimeBoolean(bool);
  void setSpeedBoolean(bool);
  void setProgressBoolean(bool);
  void setPotentialEnergyBoolean(bool);
  void setKineticEnergyBoolean(bool);
  void setTotalEnergyBoolean(bool);
  void setTemperatureBoolean(bool);
  void setVolumeBoolean(bool);
  void setDensityBoolean(bool);
  void setPlatformType(int);
  void setPrecisionType(int);
  void setMinimize(int);
  void setMinimizeSteps(int);
};
} // namespace QtPlugins
} // namespace Avogadro

#endif
