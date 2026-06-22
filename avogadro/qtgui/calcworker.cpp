/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calcworker.h"

#include <avogadro/calc/energycalculator.h>
#include <avogadro/calc/energyoptimizer.h>

#include <algorithm>
#include <iterator>

namespace Avogadro::QtGui {

CalcWorker::CalcWorker(QObject* parent) : QObject(parent)
{
  qRegisterMetaType<Eigen::VectorXd>("Eigen::VectorXd");
  qRegisterMetaType<Core::Molecule>("Avogadro::Core::Molecule");
  qRegisterMetaType<Calc::OptimizationOptions>(
    "Avogadro::Calc::OptimizationOptions");
  qRegisterMetaType<std::vector<Core::Constraint>>(
    "std::vector<Avogadro::Core::Constraint>");
  qRegisterMetaType<Calc::EnergyCalculator*>(
    "Avogadro::Calc::EnergyCalculator*");
  qRegisterMetaType<std::vector<Eigen::VectorXd>>(
    "std::vector<Eigen::VectorXd>");
  qRegisterMetaType<std::vector<double>>("std::vector<double>");
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
  m_optState = Calc::OptimizerState{};

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

  bool ok = Calc::optimizeSteps(*m_calc, positions, options, &m_optState);

  if (m_cancelled) {
    emit optimizeFinished(positions, Eigen::VectorXd(), 0.0, true);
    return;
  }

  // Read (energy, gradient) from optimizer state. The optimizer already
  // computed them at the final positions of this chunk; no extra
  // evaluate() needed.
  Eigen::VectorXd gradient = m_optState.gradient;
  double energy = m_optState.energy;
  if (gradient.size() != positions.size()) {
    // Fallback for algorithms that don't populate state (shouldn't happen
    // with the current dispatch; defensive only).
    gradient = Eigen::VectorXd::Zero(positions.size());
    energy = m_calc->evaluate(positions, &gradient);
  }

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

void CalcWorker::runEvaluateBatch(std::vector<Eigen::VectorXd> coordsList,
                                  bool computeGradient, int chunkSize)
{
  std::vector<double> energies;
  std::vector<Eigen::VectorXd> gradients;

  if (!m_calc || coordsList.empty() || m_cancelled) {
    emit evaluateBatchFinished(energies, gradients);
    return;
  }

  const int total = static_cast<int>(coordsList.size());

  // Memory-bounded auto chunk size: cap the per-chunk payload (which also
  // bounds the equally-sized gradient response) to a sane budget.
  if (chunkSize <= 0) {
    constexpr std::size_t byteBudget = 32 * 1024 * 1024; // ~32 MB
    constexpr std::size_t maxFramesCap = 256;
    const std::size_t frameDoubles =
      static_cast<std::size_t>(coordsList.front().size());
    const std::size_t frameBytes =
      std::max<std::size_t>(1, frameDoubles * sizeof(double));
    std::size_t frames = byteBudget / frameBytes;
    frames = std::clamp<std::size_t>(frames, 1, maxFramesCap);
    chunkSize = static_cast<int>(frames);
  }

  energies.reserve(coordsList.size());
  if (computeGradient)
    gradients.reserve(coordsList.size());

  for (std::size_t start = 0; start < coordsList.size();
       start += static_cast<std::size_t>(chunkSize)) {
    if (m_cancelled)
      break;

    const std::size_t end =
      std::min(coordsList.size(), start + static_cast<std::size_t>(chunkSize));
    std::vector<Eigen::VectorXd> chunk(coordsList.begin() + start,
                                       coordsList.begin() + end);

    if (computeGradient) {
      std::vector<Eigen::VectorXd> chunkGrads;
      m_calc->gradientBatch(chunk, chunkGrads);
      // Energy alongside the gradient so callers always get both.
      std::vector<double> chunkEnergies = m_calc->valueBatch(chunk);
      energies.insert(energies.end(), chunkEnergies.begin(),
                      chunkEnergies.end());
      gradients.insert(gradients.end(),
                       std::make_move_iterator(chunkGrads.begin()),
                       std::make_move_iterator(chunkGrads.end()));
    } else {
      std::vector<double> chunkEnergies = m_calc->valueBatch(chunk);
      energies.insert(energies.end(), chunkEnergies.begin(),
                      chunkEnergies.end());
    }

    emit batchProgress(static_cast<int>(end), total);
  }

  emit evaluateBatchFinished(energies, gradients);
}

void CalcWorker::cancel()
{
  m_cancelled = true;
}

} // namespace Avogadro::QtGui
