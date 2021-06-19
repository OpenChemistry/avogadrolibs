/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SLATERSETCONCURRENT_H
#define AVOGADRO_QTPLUGINS_SLATERSETCONCURRENT_H

#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QObject>

namespace Avogadro {

namespace Core {
class Cube;
class Molecule;
class SlaterSet;
class SlaterSetTools;
}

namespace QtPlugins {

struct SlaterShell;

/**
 * @brief The SlaterSetConcurrent class uses SlaterSetTools to calculate values
 * of electronic structure properties from quantum output read in.
 * @author Marcus D. Hanwell
 */

class SlaterSetConcurrent : public QObject
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
}
}

#endif // AVOGADRO_QTPLUGINS_SLATERSETCONCURRENT_H
