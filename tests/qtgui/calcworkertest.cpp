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

// An energy model with a constant energy and a constant, non-zero gradient:
// the line search can never lower the energy, so the optimizer reports a stall
// after a few iterations, as it does at the noise floor of a real model.
class FlatEnergy : public EnergyCalculator
{
public:
  EnergyCalculator* newInstance() const override { return new FlatEnergy; }
  std::string identifier() const override { return "FlatEnergy"; }
  std::string name() const override { return "FlatEnergy"; }
  std::string description() const override { return "Test energy"; }
  Molecule::ElementMask elements() const override
  {
    return Molecule::ElementMask();
  }
  void setMolecule(Molecule*) override {}
  Real value(const Eigen::VectorXd&) override { return 1.0; }
  void gradient(const Eigen::VectorXd& x, Eigen::VectorXd& grad) override
  {
    grad = Eigen::VectorXd::Ones(x.size());
  }
};

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
  // The chunk reports the iterations it really ran and whether it stalled.
  const int iterationsRun = args.at(4).toInt();
  const bool stalled = args.at(5).toBool();
  // A 5-iteration L-BFGS chunk from a stretched H2 does not stall (a stall
  // needs three consecutive steps below 1e-10 Angstrom), so it runs them all.
  EXPECT_EQ(iterationsRun, 5);
  EXPECT_FALSE(stalled);

  EXPECT_TRUE(std::isfinite(energy));
  EXPECT_EQ(newPositions.size(), 6);
  EXPECT_TRUE(newPositions.allFinite());
  // Energy should decrease after optimization
  EXPECT_LT(energy, initialEnergy);

  thread->quit();
  thread->wait(2000);
}

TEST(CalcWorkerTest, optimizeChunkReportsStall)
{
  ensureApp();
  Molecule mol = buildH2();

  auto* calc = new FlatEnergy();
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

  OptimizationOptions options;
  options.chunkIterations = 50;

  QMetaObject::invokeMethod(
    worker, "runOptimizeChunk", Qt::QueuedConnection,
    Q_ARG(Eigen::VectorXd, positions),
    Q_ARG(Avogadro::Calc::OptimizationOptions, options));
  ASSERT_TRUE(waitForSignal(optSpy));

  QList<QVariant> args = optSpy.takeFirst();
  EXPECT_FALSE(args.at(3).toBool()); // ok
  const int iterationsRun = args.at(4).toInt();
  EXPECT_GT(iterationsRun, 0);
  EXPECT_LE(iterationsRun, 50);
  EXPECT_TRUE(args.at(5).toBool()); // stalled

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
  EXPECT_EQ(args.at(4).toInt(), 0);
  EXPECT_FALSE(args.at(5).toBool());

  thread->quit();
  thread->wait(2000);
}
