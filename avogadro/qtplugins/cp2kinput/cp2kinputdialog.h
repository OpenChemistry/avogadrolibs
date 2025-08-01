/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef CP2KINPUTDIALOG_H
#define CP2KINPUTDIALOG_H

#include <QButtonGroup>
#include <QDialog>
#include <QModelIndex>

#include "ui_cp2kinputdialog.h"

#include <QtCore/QSettings>

class QJsonObject;

namespace Avogadro {
namespace MoleQueue {
class JobObject;
}
namespace QtGui {
class Molecule;
}

namespace QtPlugins {
// class GamessHighlighter;

class Cp2kInputDialog : public QDialog
{
  Q_OBJECT

  enum CalculateOption
  {
    CalculateEnergy = 0,
    CalculateEnergyAndForces,
    CalculateMolecularDynamics,
    CalculateGeometryOptimization,

    CalculateCount
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

public:
  explicit Cp2kInputDialog(QWidget* parent_ = nullptr,
                           Qt::WindowFlags f = Qt::WindowFlags());
  ~Cp2kInputDialog() override;

  void setMolecule(QtGui::Molecule* mol);

signals:
  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const Avogadro::MoleQueue::JobObject& job);

protected:
  void showEvent(QShowEvent* e) override;

private slots:
  void updatePreviewText();

  void defaultsClicked();
  void resetClicked();
  void generateClicked();
  void computeClicked();

  void updateTitlePlaceholder();

private:
  void connectBasic();
  void connectPreview();
  void connectButtons();

  void buildOptions();
  void updateOptionCache();
  void restoreOptionCache();

  void buildCalculateOptions();
  void buildFunctionalOptions();
  void buildMethodOptions();
  void buildBasisOptions();
  void buildStateOptions();
  void buildMultiplicityOptions();
  void buildChargeOptions();

  void buildEWALDTypeOptions();

  void buildSCFGuessOptions();
  void buildOTMinimizerOptions();

  void setBasicDefaults();

  /// @return valid values for CP2K RUN_TYPE
  static QString fromCalcEnum(CalculateOption option);
  QString generateJobTitle() const;

  Ui::Cp2kInputDialog ui;
  QtGui::Molecule* m_molecule;
  // GamessHighlighter *m_highlighter;

  bool m_updatePending;
  QMap<QComboBox*, int> m_optionCache;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // CP2KINPUTDIALOG_H
