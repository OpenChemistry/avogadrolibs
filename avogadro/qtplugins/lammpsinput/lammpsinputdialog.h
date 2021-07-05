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

#ifndef LAMMPSINPUTDIALOG_H
#define LAMMPSINPUTDIALOG_H

#include "ui_lammpsinputdialog.h"

#include <QHash>
#include <QtCore/QSettings>

class QJsonObject;
class QTextEdit;

namespace Avogadro {
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
class LammpsInputDialog : public QDialog
{
  Q_OBJECT

public:
  explicit LammpsInputDialog(QWidget* parent = nullptr,
                             Qt::WindowFlags flag = 0);
  ~LammpsInputDialog();

  void readSettings(QSettings&);
  void writeSettings(QSettings&) const;

  enum unitType
  {
    lj,
    real,
    metal,
    si,
    cgs,
    u_electron
  };
  enum dimensionType
  {
    d2,
    d3
  };
  enum boundaryType
  {
    p,
    s,
    f,
    m,
    fs,
    fm
  };
  enum atomStyle
  {
    angle,
    atomic,
    bond,
    charge,
    dipole,
    a_electron,
    ellipsoid,
    full,
    line,
    meso,
    molecular,
    peri,
    sphere,
    tri,
    wavepacket
  };
  enum waterPotential
  {
    NONE,
    SPC,
    SPCE
  };
  void setMolecule(QtGui::Molecule* molecule);
  enum ensemble
  {
    NVT,
    NVE
  };
  enum velocityDist
  {
    gaussian,
    uniform
  };
  enum thermoStyle
  {
    one,
    multi
  };

protected:
  /**
   * Reimplemented to update the dialog when it is shown
   */
  void showEvent(QShowEvent* event);

private:
  Ui::LammpsInputDialog ui;
  QtGui::Molecule* m_molecule;

  // QString m_title;
  QString m_readData;
  unitType m_unitType;
  QString m_title;
  QString m_savePath;
  dimensionType m_dimensionType;
  boundaryType m_xBoundaryType;
  boundaryType m_yBoundaryType;
  boundaryType m_zBoundaryType;
  atomStyle m_atomStyle;
  waterPotential m_waterPotential;

  // coordType m_coordType;
  ensemble m_ensemble;
  double m_temperature;
  int m_nhChain;
  double m_timeStep;
  int m_runSteps;
  int m_xReplicate;
  int m_yReplicate;
  int m_zReplicate;
  QString m_dumpXYZ;
  int m_dumpStep;
  velocityDist m_velocityDist;
  double m_velocityTemp;
  bool m_zeroMOM;
  bool m_zeroL;
  thermoStyle m_thermoStyle;
  int m_thermoInterval;

  QString m_output;
  bool m_dirty;
  bool m_warned;
  bool readData;

  QTextEdit* m_jobEdit;
  QTextEdit* m_moleculeEdit;
  QString m_moleculeFileName;
  QString m_jobFileName;

  // Generate an input deck as a string
  QString generateInputDeck();
  QString getUnitType(unitType t);
  QString getAtomStyle(atomStyle t);
  QString getDimensionType(dimensionType t);
  QString getXBoundaryType(boundaryType t);
  QString getYBoundaryType(boundaryType t);
  QString getZBoundaryType(boundaryType t);
  QString getWaterPotential(waterPotential t);
  QString getEnsemble(ensemble t);
  QString getVelocityDist(velocityDist t);
  QString getZeroMOM();
  QString getZeroL();
  QString getThermoStyle(thermoStyle t);
  // Translate enums to strings
  // QString getCalculationType(calculationType t);
  // QString getWavefunction(void);
  // QString getTheoryType(theoryType t);
  // QString getBasisType(basisType t);

  // Enable/disable form elements
  void deckDirty(bool);
  void determineAtomTypesSPC(int& hyd, int& oxy);
  void addMoleculeDataTab();

  // system typing
  QHash<QString, int> AtomType;
  QHash<QString, double> AtomMass;
  QHash<QString, double>::iterator itr;

public Q_SLOTS:
  void updatePreviewText();

private Q_SLOTS:
  //! Button Slots
  void textEditModified();
  void resetClicked();
  void generateClicked();
  void enableFormClicked();

  void setTitle();
  void setReadData();

  void setUnits(int);
  void setAtomStyle(int);
  void setDimensionType(int);
  void setXBoundaryType(int);
  void setYBoundaryType(int);
  void setZBoundaryType(int);

  void setWaterPotential(int);

  void setEnsemble(int);
  void setTemperature(double);
  void setNHChain(int);

  void setTimeStep(double);
  void setRunSteps(int);
  void setXReplicate(int);
  void setYReplicate(int);
  void setZReplicate(int);
  void setDumpXYZ();
  void setDumpStep(int);

  void setVelocityDist(int);
  void setVelocityTemp(double);
  void setZeroMOM(bool);
  void setZeroL(bool);
  void setThermoStyle(int);
  void setThermoInterval(int);
};
}
}

#endif
