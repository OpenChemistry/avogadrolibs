/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/calc/energymanager.h>
#include <avogadro/calc/lennardjones.h>
#include <avogadro/core/molecule.h>
#include <avogadro/qtgui/calcworker.h>

#include <QCoreApplication>
#include <QSignalSpy>
#include <QThread>
#include <QTimer>

using Avogadro::Real;
using Avogadro::Calc::EnergyCalculator;
using Avogadro::Calc::LennardJones;
using Avogadro::Calc::OptimizationOptions;
using Avogadro::Core::Molecule;
using Avogadro::QtGui::CalcWorker;

namespace {

// Ensure a QCoreApplication exists (required for cross-thread signal delivery).
// The test binary uses gtest_main which does not create one.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "CalcWorkerTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

// Build a simple H2 molecule for testing
Molecule buildH2()
{
  Molecule mol;
  mol.addAtom(1);
  mol.addAtom(1);
  mol.setAtomPosition3d(0, Avogadro::Vector3(0.0, 0.0, 0.0));
  mol.setAtomPosition3d(1, Avogadro::Vector3(0.0, 0.0, 1.5));
  mol.addBond(0, 1);
  return mol;
}

// Helper: spin the Qt event loop until a QSignalSpy has at least one signal
// or a timeout is reached. Returns true if signal was received.
bool waitForSignal(QSignalSpy& spy, int timeoutMs = 5000)
{
  if (spy.count() > 0)
    return true;
  return spy.wait(timeoutMs);
}

} // namespace

TEST(CalcWorkerTest, evaluateEnergy)
{
  ensureApp();
  Molecule mol = buildH2();

  auto* calc = new LennardJones();
  Eigen::VectorXd mask = Eigen::VectorXd::Ones(6);

  auto* thread = new QThread;
  auto* worker = new CalcWorker;
  worker->moveToThread(thread);
  QObject::connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  QObject::connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  thread->start();

  QSignalSpy readySpy(worker, &CalcWorker::calculatorReady);
  QSignalSpy evalSpy(worker, &CalcWorker::evaluateFinished);

  QMetaObject::invokeMethod(worker, "initCalculator", Qt::QueuedConnection,
                            Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
                            Q_ARG(Avogadro::Core::Molecule, mol),
                            Q_ARG(Eigen::VectorXd, mask),
                            Q_ARG(std::vector<Avogadro::Core::Constraint>,
                                  std::vector<Avogadro::Core::Constraint>()));

  ASSERT_TRUE(waitForSignal(readySpy));

  // Get positions as a flat vector
  Eigen::VectorXd positions(6);
  positions << 0.0, 0.0, 0.0, 0.0, 0.0, 1.5;

  QMetaObject::invokeMethod(worker, "runEvaluate", Qt::QueuedConnection,
                            Q_ARG(Eigen::VectorXd, positions),
                            Q_ARG(bool, false));

  ASSERT_TRUE(waitForSignal(evalSpy));

  // Check we got a finite energy
  QList<QVariant> args = evalSpy.takeFirst();
  double energy = args.at(1).toDouble();
  EXPECT_TRUE(std::isfinite(energy));

  thread->quit();
  thread->wait(2000);
}

TEST(CalcWorkerTest, evaluateGradient)
{
  ensureApp();
  Molecule mol = buildH2();

  auto* calc = new LennardJones();
  Eigen::VectorXd mask = Eigen::VectorXd::Ones(6);

  auto* thread = new QThread;
  auto* worker = new CalcWorker;
  worker->moveToThread(thread);
  QObject::connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  QObject::connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  thread->start();

  QSignalSpy readySpy(worker, &CalcWorker::calculatorReady);
  QSignalSpy evalSpy(worker, &CalcWorker::evaluateFinished);

  QMetaObject::invokeMethod(worker, "initCalculator", Qt::QueuedConnection,
                            Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
                            Q_ARG(Avogadro::Core::Molecule, mol),
                            Q_ARG(Eigen::VectorXd, mask),
                            Q_ARG(std::vector<Avogadro::Core::Constraint>,
                                  std::vector<Avogadro::Core::Constraint>()));

  ASSERT_TRUE(waitForSignal(readySpy));

  Eigen::VectorXd positions(6);
  positions << 0.0, 0.0, 0.0, 0.0, 0.0, 1.5;

  QMetaObject::invokeMethod(worker, "runGradient", Qt::QueuedConnection,
                            Q_ARG(Eigen::VectorXd, positions));

  ASSERT_TRUE(waitForSignal(evalSpy));

  QList<QVariant> args = evalSpy.takeFirst();
  auto gradient = args.at(0).value<Eigen::VectorXd>();
  double energy = args.at(1).toDouble();

  EXPECT_TRUE(std::isfinite(energy));
  EXPECT_EQ(gradient.size(), 6);
  EXPECT_TRUE(gradient.allFinite());
  // Gradient should be non-zero for a non-equilibrium geometry
  EXPECT_GT(gradient.norm(), 0.0);

  thread->quit();
  thread->wait(2000);
}

TEST(CalcWorkerTest, optimizeChunk)
{
  ensureApp();
  Molecule mol = buildH2();

  auto* calc = new LennardJones();
  Eigen::VectorXd mask = Eigen::VectorXd::Ones(6);

  auto* thread = new QThread;
  auto* worker = new CalcWorker;
  worker->moveToThread(thread);
  QObject::connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  QObject::connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  thread->start();

  QSignalSpy readySpy(worker, &CalcWorker::calculatorReady);
  QSignalSpy optSpy(worker, &CalcWorker::optimizeFinished);

  QMetaObject::invokeMethod(worker, "initCalculator", Qt::QueuedConnection,
                            Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
                            Q_ARG(Avogadro::Core::Molecule, mol),
                            Q_ARG(Eigen::VectorXd, mask),
                            Q_ARG(std::vector<Avogadro::Core::Constraint>,
                                  std::vector<Avogadro::Core::Constraint>()));

  ASSERT_TRUE(waitForSignal(readySpy));

  Eigen::VectorXd positions(6);
  positions << 0.0, 0.0, 0.0, 0.0, 0.0, 1.5;

  // Compute initial energy for comparison
  LennardJones lj;
  lj.setMolecule(&mol);
  double initialEnergy = lj.value(positions);

  OptimizationOptions options;
  options.chunkIterations = 5;

  QMetaObject::invokeMethod(
    worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, positions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, options));

  ASSERT_TRUE(waitForSignal(optSpy));

  QList<QVariant> args = optSpy.takeFirst();
  auto newPositions = args.at(0).value<Eigen::VectorXd>();
  auto gradient = args.at(1).value<Eigen::VectorXd>();
  double energy = args.at(2).toDouble();

  EXPECT_TRUE(std::isfinite(energy));
  EXPECT_EQ(newPositions.size(), 6);
  EXPECT_TRUE(newPositions.allFinite());
  // Energy should decrease after optimization
  EXPECT_LT(energy, initialEnergy);

  thread->quit();
  thread->wait(2000);
}

TEST(CalcWorkerTest, cancel)
{
  ensureApp();
  Molecule mol = buildH2();

  auto* calc = new LennardJones();
  Eigen::VectorXd mask = Eigen::VectorXd::Ones(6);

  auto* thread = new QThread;
  auto* worker = new CalcWorker;
  worker->moveToThread(thread);
  QObject::connect(thread, &QThread::finished, worker, &QObject::deleteLater);
  QObject::connect(thread, &QThread::finished, thread, &QObject::deleteLater);
  thread->start();

  QSignalSpy readySpy(worker, &CalcWorker::calculatorReady);

  QMetaObject::invokeMethod(worker, "initCalculator", Qt::QueuedConnection,
                            Q_ARG(Avogadro::Calc::EnergyCalculator*, calc),
                            Q_ARG(Avogadro::Core::Molecule, mol),
                            Q_ARG(Eigen::VectorXd, mask),
                            Q_ARG(std::vector<Avogadro::Core::Constraint>,
                                  std::vector<Avogadro::Core::Constraint>()));

  ASSERT_TRUE(waitForSignal(readySpy));

  // Cancel before requesting work
  worker->cancel();

  QSignalSpy optSpy(worker, &CalcWorker::optimizeFinished);

  Eigen::VectorXd positions(6);
  positions << 0.0, 0.0, 0.0, 0.0, 0.0, 1.5;

  OptimizationOptions options;
  options.chunkIterations = 5;

  QMetaObject::invokeMethod(
    worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, positions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, options));

  ASSERT_TRUE(waitForSignal(optSpy));

  // Should report converged=true due to cancellation
  QList<QVariant> args = optSpy.takeFirst();
  bool converged = args.at(3).toBool();
  EXPECT_TRUE(converged);

  thread->quit();
  thread->wait(2000);
}
