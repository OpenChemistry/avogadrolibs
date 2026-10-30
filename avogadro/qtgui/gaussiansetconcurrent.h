/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_GAUSSIANSETCONCURRENT_H
#define AVOGADRO_QTGUI_GAUSSIANSETCONCURRENT_H

#include "avogadroqtguiexport.h"

#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QObject>

#include <memory>

namespace Avogadro {

namespace Core {
class BasisSet;
class Cube;
class Molecule;
class GaussianSet;
class GaussianSetTools;
} // namespace Core

namespace QtGui {

struct GaussianShell;

/**
 * @brief The GaussianSetConcurrent class uses GaussianSetTools to calculate
 * values of electronic structure properties from quantum output read in.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT GaussianSetConcurrent : public QObject
{
  Q_OBJECT

public:
  explicit GaussianSetConcurrent(QObject* p = nullptr);
  ~GaussianSetConcurrent() override;

  /**
   * Prepare a calculation on the basis set of @p mol. Call this before each
   * calculation: the calculator holds the basis set only until that job
   * finishes, and refuses to start another without a new setMolecule().
   *
   * This takes the molecule's mutable basis set, because setting up a
   * calculation writes into it, so a basis set an undo snapshot shares is
   * copied first.
   */
  void setMolecule(Core::Molecule* mol);

  /**
   * @name Calculations
   * Fill @p cube on worker threads; finished() is emitted when done.
   *
   * The workers write into @p cube until the calculation finishes or is
   * cancelled, so the caller must own it and keep it alive for the whole
   * job. Do not pass a cube the molecule holds: fill one of your own, then
   * hand it over with Molecule::addCube() or setCube() taking a
   * std::unique_ptr. A cancelled calculation leaves the cube partly filled
   * (watcher().isCanceled() tells), so it should be discarded.
   * @return False, with nothing started, if the basis set cannot be used.
   * @{
   */
  bool calculateMolecularOrbital(Core::Cube* cube, unsigned int state,
                                 bool beta = false);
  bool calculateElectronDensity(Core::Cube* cube);
  bool calculateSpinDensity(Core::Cube* cube);
  /** @} */

  QFutureWatcher<void>& watcher() { return m_watcher; }

  /**
   * Cancel every running calculation and wait for the worker threads to stop.
   *
   * A running calculation reads the molecule's basis set and writes into the
   * cube it was handed, so anything about to delete either has to stop the
   * work first. The calculation may belong to a different part of the
   * application than the code doing the deleting, which is why this reaches
   * every instance rather than just one.
   */
  static void cancelAllCalculations();

signals:
  /**
   * Emitted when the calculation is complete.
   */
  void finished();

private slots:
  /**
   * Slot to set the cube data once Qt Concurrent is done
   */
  void calculationComplete();

private:
  QFuture<void> m_future;
  QFutureWatcher<void> m_watcher;
  QVector<GaussianShell>* m_gaussianShells;

  Core::GaussianSet* m_set;
  Core::GaussianSetTools* m_tools;
  // Keeps the basis set the workers read alive for the job, even if the
  // molecule later detaches from it and hands it to an undo snapshot.
  std::shared_ptr<const Core::BasisSet> m_basisHandle;

  bool setUpCalculation(Core::Cube* cube, unsigned int state,
                        void (*func)(GaussianShell&));

  /**
   * Cancel any in-flight calculation and block until the worker threads have
   * stopped. Must be called before anything they reference is freed.
   */
  void cancelAndWait();

  static void processOrbital(GaussianShell& shell);
  static void processDensity(GaussianShell& shell);
  static void processSpinDensity(GaussianShell& shell);
};
} // namespace QtGui
} // namespace Avogadro

#endif // GAUSSIANSETCONCURRENT_H
