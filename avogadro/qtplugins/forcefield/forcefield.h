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

#include <QtCore/QElapsedTimer>
#include <QtCore/QList>
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

  void registerCommands() override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

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
  void batchEnergy();
  void batchForces();
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
  void onBatchDone(std::vector<double> energies,
                   std::vector<Eigen::VectorXd> gradients);
  void onWorkerReady();

private:
  // Which command (if any) is waiting on the in-flight worker run. GUI-
  // triggered runs leave this at None; onEnergyDone()/onForcesDone()/
  // onOptimizeChunkDone() branch on it to decide whether to show a dialog
  // or report a command result, and cleanupWorker() uses it to fail a
  // command left pending when the worker is torn down out from under it
  // (e.g. setMolecule() switching molecules mid-run).
  enum class PendingCommand
  {
    None,
    Energy,
    Forces,
    Optimize
  };

  // Effective parameters for the in-flight optimization run. Populated once
  // at the start of the run (from QSettings-backed members for the GUI, or
  // from command options for the "optimize" command) and read everywhere
  // mid-run instead of m_maxSteps/m_gradientTolerance/m_tolerance, since a
  // per-call value must never be written back to those members.
  struct OptimizeRunOptions
  {
    unsigned int maxSteps = 100;
    double gradientTolerance = 1.0e-4;
    double tolerance = 1.0e-6;
  };

  void cleanupWorker();
  void startWorker(const std::string& methodId);
  void sendInitCalculator();
  // Gather every coordinate set as a flat 3N vector (non-destructive).
  std::vector<Eigen::VectorXd> gatherCoordinateSets() const;
  // Shared entry point for the two batch actions.
  void runBatch(bool computeGradient);

  // Resolve the force field a caller asked for. An empty methodOption means
  // "use whatever the GUI would" (setupMethod(), then m_methodName). A
  // non-empty methodOption must be compatible with the current molecule
  // (per EnergyManager::identifiersForMolecule()) or this fails with a
  // message saying whether the id is unknown or merely incompatible; there
  // is no fallback to the recommended method for an explicit request.
  bool resolveMethod(const QString& methodOption, std::string& methodId,
                     QString& errorMessage);

  // Compute-only entry points shared by the GUI slots and handleCommand().
  // All UI (message boxes, the progress dialog) stays in the GUI slots;
  // these only touch the molecule/worker and, on success, set
  // m_pendingCommand so the completion slot knows how to report back.
  void startEnergyCalculation(const std::string& methodId,
                              PendingCommand pending);
  void startForcesCalculation(const std::string& methodId,
                              PendingCommand pending);
  void startOptimizeCalculation(const std::string& methodId,
                                const OptimizeRunOptions& runOptions,
                                PendingCommand pending);

  // Why an optimize run stopped, reported to the "optimize" command as
  // "reason" so a script knows which criterion ended the run without
  // guessing from "converged" alone. "optimizerStopped" means the worker's
  // own converged flag was set -- not a discovered minimum: CalcWorker only
  // sets it when it could not run the chunk at all (no calculator, or
  // cancelled), or (defensively) for a malformed chunk size, never on
  // finding one. "gradient" and "energy" are converged: true; "maxSteps",
  // "nonFinite" and "optimizerStopped" are converged: false.
  enum class ConvergenceReason
  {
    None,
    Gradient,
    Energy,
    OptimizerStopped,
    MaxSteps,
    NonFinite
  };
  static QString convergenceReasonName(ConvergenceReason reason);

  // handleCommand() helpers, one per registered command.
  void handleListForceFieldsCommand();
  void handleEnergyCommand(const QVariantMap& options);
  void handleForcesCommand(const QVariantMap& options);
  void handleOptimizeCommand(const QVariantMap& options);
  void handleFreezeSelectedCommand();
  void handleUnfreezeSelectedCommand();
  void handleFreezeAxisCommand(const QVariantMap& options);

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
  // Threads that did not stop within cleanupWorker()'s bounded wait. They
  // must remain alive until their work finishes; deleting a running QThread
  // aborts the process.
  QList<QThread*> m_retiredThreads;
  QProgressDialog* m_progressDialog = nullptr;
  bool m_optimizing = false;
  // True while a batch energy/forces run is in flight.
  bool m_batchRunning = false;
  // Whether the in-flight batch run requested gradients.
  bool m_batchGradient = false;
  // Set by startEnergyCalculation()/startForcesCalculation()/
  // startOptimizeCalculation() once the worker is confirmed running for a
  // command (None for a GUI-triggered run). See the enum's comment.
  PendingCommand m_pendingCommand = PendingCommand::None;
  // The method identifier the in-flight (or most recently finished) run
  // actually used -- may differ from m_methodName for a command that named
  // its own "method".
  std::string m_activeMethodName;
  // Effective options for the in-flight optimize run; see the struct.
  OptimizeRunOptions m_runOptions;
  // Iterations completed (sum of chunk sizes already executed). Used to
  // bound total work and drive the progress dialog now that the chunk
  // size adapts per chunk.
  unsigned int m_iterationsDone = 0;
  Eigen::VectorXd m_lastPositions;
  double m_lastEnergy = 0.0;
  // Whether m_lastEnergy holds a value from a previous chunk. Distinguishes
  // "no previous chunk yet" from "previous energy happened to be 0.0", which
  // an equality check against 0.0 cannot.
  bool m_hasPreviousEnergy = false;
  Calc::OptimizationOptions m_optOptions;
  // Timer for chunk wall-clock measurement (round-trip from dispatch to
  // optimizeFinished, so dispatch overhead counts toward the frame budget).
  QElapsedTimer m_chunkTimer;

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
