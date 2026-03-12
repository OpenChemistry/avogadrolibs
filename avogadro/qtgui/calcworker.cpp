/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calcworker.h"

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>

namespace Avogadro::QtGui {

CalcWorker::CalcWorker(QObject* parent) : QObject(parent)
{
  static bool registered = false;
  if (!registered) {
    qRegisterMetaType<Eigen::VectorXd>("Eigen::VectorXd");
    qRegisterMetaType<Core::Molecule>("Avogadro::Core::Molecule");
    qRegisterMetaType<Calc::OptimizationOptions>(
      "Avogadro::Calc::OptimizationOptions");
    qRegisterMetaType<std::vector<Core::Constraint>>(
      "std::vector<Avogadro::Core::Constraint>");
    qRegisterMetaType<Calc::EnergyCalculator*>(
      "Avogadro::Calc::EnergyCalculator*");
    registered = true;
  }
}

CalcWorker::~CalcWorker() = default;

void CalcWorker::initCalculator(Calc::EnergyCalculator* calculator,
                                Core::Molecule molSnapshot,
                                Eigen::VectorXd mask,
                                std::vector<Core::Constraint> constraints)
{
  m_cancelled = false;
  m_calc.reset(calculator);
  m_molSnapshot = std::move(molSnapshot);

  // setMolecule on this thread so QProcess gets correct affinity
  m_calc->setMolecule(&m_molSnapshot);
  m_calc->setMask(mask);
  m_calc->setConstraints(constraints);

  emit calculatorReady();
}

void CalcWorker::runOptimizeChunk(Eigen::VectorXd positions,
                                  Calc::OptimizationOptions options)
{
  if (!m_calc || m_cancelled) {
    emit optimizeFinished(positions, Eigen::VectorXd(), 0.0, true);
    return;
  }

  bool ok = Calc::optimizeSteps(*m_calc, positions, options);

  if (m_cancelled) {
    emit optimizeFinished(positions, Eigen::VectorXd(), 0.0, true);
    return;
  }

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(positions.size());
  double energy = m_calc->evaluate(positions, &gradient);

  emit optimizeFinished(positions, gradient, energy, !ok);
}

void CalcWorker::runEvaluate(Eigen::VectorXd positions, bool computeGradient)
{
  if (!m_calc || m_cancelled) {
    emit evaluateFinished(Eigen::VectorXd(), 0.0);
    return;
  }

  Eigen::VectorXd gradient;
  Eigen::VectorXd* gradPtr = nullptr;
  if (computeGradient) {
    gradient = Eigen::VectorXd::Zero(positions.size());
    gradPtr = &gradient;
  }

  double energy = m_calc->evaluate(positions, gradPtr);

  emit evaluateFinished(gradient, energy);
}

void CalcWorker::runGradient(Eigen::VectorXd positions)
{
  if (!m_calc || m_cancelled) {
    emit evaluateFinished(Eigen::VectorXd(), 0.0);
    return;
  }

  Eigen::VectorXd gradient = Eigen::VectorXd::Zero(positions.size());
  double energy = m_calc->evaluate(positions, &gradient);
  emit evaluateFinished(gradient, energy);
}

void CalcWorker::cancel()
{
  m_cancelled = true;
}

} // namespace Avogadro::QtGui
