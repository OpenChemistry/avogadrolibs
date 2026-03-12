/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CALCWORKER_H
#define AVOGADRO_QTGUI_CALCWORKER_H

#include "avogadroqtguiexport.h"

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <QObject>
#include <QThread>

#include <Eigen/Core>

#include <atomic>
#include <memory>
#include <vector>

Q_DECLARE_METATYPE(Eigen::VectorXd)
Q_DECLARE_METATYPE(Avogadro::Core::Molecule)
Q_DECLARE_METATYPE(Avogadro::Calc::OptimizationOptions)
Q_DECLARE_METATYPE(std::vector<Avogadro::Core::Constraint>)
Q_DECLARE_METATYPE(Avogadro::Calc::EnergyCalculator*)

namespace Avogadro {

namespace QtGui {

/**
 * @class CalcWorker calcworker.h <avogadro/qtgui/calcworker.h>
 * @brief Worker object that runs EnergyCalculator computations on a
 *        dedicated QThread.
 *
 * The worker owns a cloned EnergyCalculator and a Core::Molecule snapshot.
 * All heavy computation (energy, gradient, optimization steps) happens on
 * the worker thread; results are delivered back to the main thread via
 * queued signal/slot connections.
 *
 * Typical usage:
 * @code
 *   auto* thread = new QThread;
 *   auto* worker = new CalcWorker;
 *   worker->moveToThread(thread);
 *   connect(thread, &QThread::finished, worker, &QObject::deleteLater);
 *   connect(thread, &QThread::finished, thread, &QObject::deleteLater);
 *   thread->start();
 *
 *   // Initialize calculator on the worker thread (important for QProcess)
 *   QMetaObject::invokeMethod(worker, "initCalculator",
 *     Qt::QueuedConnection,
 *     Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
 *     Q_ARG(Avogadro::Core::Molecule, molSnapshot),
 *     Q_ARG(Eigen::VectorXd, mask),
 *     Q_ARG(std::vector<Avogadro::Core::Constraint>, constraints));
 * @endcode
 */
class AVOGADROQTGUI_EXPORT CalcWorker : public QObject
{
  Q_OBJECT

public:
  explicit CalcWorker(QObject* parent = nullptr);
  ~CalcWorker() override;

signals:
  /**
   * Emitted after each optimization chunk completes.
   * @param positions The updated coordinate vector.
   * @param gradient The gradient at the new positions.
   * @param energy The energy at the new positions.
   * @param converged True if optimization could not continue.
   */
  void optimizeFinished(Eigen::VectorXd positions, Eigen::VectorXd gradient,
                        double energy, bool converged);

  /**
   * Emitted after a one-shot energy/gradient evaluation.
   * @param gradient The gradient vector (empty if not requested).
   * @param energy The computed energy.
   */
  void evaluateFinished(Eigen::VectorXd gradient, double energy);

  /**
   * Emitted when the calculator has been initialized on the worker thread.
   */
  void calculatorReady();

public slots:
  /**
   * Initialize the calculator on the worker thread.
   * This MUST be called via queued connection so that setMolecule()
   * runs on the worker thread (required for QProcess affinity in
   * ScriptEnergy/OBMMEnergy).
   *
   * Takes ownership of @p calculator.
   */
  void initCalculator(Avogadro::Calc::EnergyCalculator* calculator,
                      Avogadro::Core::Molecule molSnapshot,
                      Eigen::VectorXd mask,
                      std::vector<Avogadro::Core::Constraint> constraints);

  /**
   * Run a chunk of optimization iterations.
   */
  void runOptimizeChunk(Eigen::VectorXd positions,
                        Avogadro::Calc::OptimizationOptions options);

  /**
   * Run a one-shot energy and optionally gradient evaluation.
   */
  void runEvaluate(Eigen::VectorXd positions, bool computeGradient);

  /**
   * Run a one-shot gradient evaluation.
   */
  void runGradient(Eigen::VectorXd positions);

  /**
   * Request cancellation of the current computation.
   * Thread-safe: can be called from any thread.
   */
  void cancel();

private:
  std::unique_ptr<Calc::EnergyCalculator> m_calc;
  Core::Molecule m_molSnapshot;
  std::atomic<bool> m_cancelled{ false };
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_CALCWORKER_H
