/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_SLATERSETCONCURRENT_H
#define AVOGADRO_QTGUI_SLATERSETCONCURRENT_H

#include "avogadroqtguiexport.h"

#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QObject>

namespace Avogadro {

namespace Core {
class Cube;
class Molecule;
class SlaterSet;
class SlaterSetTools;
} // namespace Core

namespace QtGui {

struct SlaterShell;

/**
 * @brief The SlaterSetConcurrent class uses SlaterSetTools to calculate values
 * of electronic structure properties from quantum output read in.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT SlaterSetConcurrent : public QObject
{
  Q_OBJECT

public:
  explicit SlaterSetConcurrent(QObject* p = nullptr);
  ~SlaterSetConcurrent() override;

  void setMolecule(Core::Molecule* mol);

  bool calculateMolecularOrbital(Core::Cube* cube, unsigned int state);
  bool calculateElectronDensity(Core::Cube* cube);
  bool calculateSpinDensity(Core::Cube* cube);

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
  QVector<SlaterShell>* m_shells;

  Core::SlaterSet* m_set;
  Core::SlaterSetTools* m_tools;

  bool setUpCalculation(Core::Cube* cube, unsigned int state,
                        void (*func)(SlaterShell&));

  /**
   * Cancel any in-flight calculation and block until the worker threads have
   * stopped. Must be called before anything they reference is freed.
   */
  void cancelAndWait();

  static void processOrbital(SlaterShell& shell);
  static void processDensity(SlaterShell& shell);
  static void processSpinDensity(SlaterShell& shell);
};
} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_SLATERSETCONCURRENT_H
