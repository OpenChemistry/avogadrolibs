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
  Core::Cube* m_cube;
  QVector<SlaterShell>* m_shells;

  Core::SlaterSet* m_set;
  Core::SlaterSetTools* m_tools;

  bool setUpCalculation(Core::Cube* cube, unsigned int state,
                        void (*func)(SlaterShell&));

  static void processOrbital(SlaterShell& shell);
  static void processDensity(SlaterShell& shell);
  static void processSpinDensity(SlaterShell& shell);
};
} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_SLATERSETCONCURRENT_H
