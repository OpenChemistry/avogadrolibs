/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FORCEFIELD_H
#define AVOGADRO_QTPLUGINS_FORCEFIELD_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>

#include <Eigen/Core>

#include <QtCore/QMultiHash>
#include <QtCore/QMultiMap>
#include <QtCore/QStringList>
#include <QtCore/QVariant>

class QAction;
class QDialog;
class QProgressDialog;
class QThread;

namespace Avogadro {

namespace Calc {
class EnergyCalculator;
}

namespace QtGui {
class CalcWorker;
}

namespace QtPlugins {

/**
 * @brief The Forcefield class implements the extension interface for
 *  forcefield (and other) optimization
 * @author Geoffrey R. Hutchison
 */
class Forcefield : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  // Currently unused - defaults to LBFGS
  enum Minimizer
  {
    SteepestDescent = 0,
    ConjugateGradients,
    LBFGS,
    FIRE,
  };

  explicit Forcefield(QObject* parent = nullptr);
  ~Forcefield() override;

  QString name() const override { return tr("Forcefield optimization"); }

  QString description() const override
  {
    return tr("Forcefield minimization, including scripts");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;
  void setupMethod();

  std::string recommendedForceField() const;

public slots:
  /**
   * Scan for new scripts in the Forcefield directories.
   */
  void refreshScripts();
  void registerScripts();
  void unregisterScripts();

  void showDialog();

  /**
   * Handle a feature registered by PackageManager.
   */
  void registerFeature(const QString& type, const QString& packageDir,
                       const QString& command, const QString& identifier,
                       const QVariantMap& metadata);

  /**
   * Handle a feature removed by PackageManager.
   */
  void unregisterFeature(const QString& type, const QString& packageDir,
                         const QString& command, const QString& identifier);

private slots:
  void energy();
  void forces();
  void optimize();
  void freezeSelected();
  void unfreezeSelected();
  void setupConstraints();

  void freezeAxis(int axis);
  void freezeX();
  void freezeY();
  void freezeZ();

  // fuse adds all pairwise distance constraints
  void fuseSelected();
  void unfuseSelected();
  void updateActions();

  // worker thread callbacks
  void onOptimizeChunkDone(Eigen::VectorXd positions, Eigen::VectorXd gradient,
                           double energy, bool converged);
  void onEnergyDone(Eigen::VectorXd gradient, double energy);
  void onForcesDone(Eigen::VectorXd gradient, double energy);
  void onWorkerReady();

private:
  void cleanupWorker();
  void startWorker();
  void sendInitCalculator();
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule = nullptr;
  Calc::EnergyCalculator* m_method = nullptr;
  std::string m_methodName;
  bool m_autodetect;

  // defaults
  Minimizer m_minimizer = LBFGS;
  unsigned int m_maxSteps = 100;
  unsigned int m_nSteps = 5;
  double m_tolerance = 1.0e-6;
  double m_gradientTolerance = 1.0e-4;
  QVariantMap m_modelUserOptions;

  QList<Calc::EnergyCalculator*> m_scripts;
  QMultiHash<QString, QString> m_packageScripts;

  // worker thread state
  QThread* m_workerThread = nullptr;
  QtGui::CalcWorker* m_worker = nullptr;
  QProgressDialog* m_progressDialog = nullptr;
  bool m_optimizing = false;
  int m_currentStep = 0;
  Eigen::VectorXd m_lastPositions;
  double m_lastEnergy = 0.0;
  Calc::OptimizationOptions m_optOptions;

  // Pending initCalculator args (set by startWorker, sent by
  // sendInitCalculator)
  Calc::EnergyCalculator* m_pendingCalc = nullptr;
  Core::Molecule m_pendingSnapshot;
  Eigen::VectorXd m_pendingMask;
  std::vector<Core::Constraint> m_pendingConstraints;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_FORCEFIELD_H
