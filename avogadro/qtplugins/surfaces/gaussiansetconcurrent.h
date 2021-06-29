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

#ifndef GAUSSIANSETCONCURRENT_H
#define GAUSSIANSETCONCURRENT_H

#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>
#include <QtCore/QObject>

namespace Avogadro {

namespace Core {
class Cube;
class Molecule;
class GaussianSet;
class GaussianSetTools;
}

namespace QtPlugins {

struct GaussianShell;

/**
 * @brief The GaussianSetConcurrent class uses GaussianSetTools to calculate
 * values of electronic structure properties from quantum output read in.
 * @author Marcus D. Hanwell
 */

class GaussianSetConcurrent : public QObject
{
  Q_OBJECT

public:
  explicit GaussianSetConcurrent(QObject* p = nullptr);
  ~GaussianSetConcurrent() override;

  void setMolecule(Core::Molecule* mol);

  bool calculateMolecularOrbital(Core::Cube* cube, unsigned int state,
                                 bool beta = false);
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
  QVector<GaussianShell>* m_gaussianShells;

  Core::GaussianSet* m_set;
  Core::GaussianSetTools* m_tools;

  bool setUpCalculation(Core::Cube* cube, unsigned int state,
                        void (*func)(GaussianShell&));

  static void processOrbital(GaussianShell& shell);
  static void processDensity(GaussianShell& shell);
  static void processSpinDensity(GaussianShell& shell);
};
}
}

#endif // GAUSSIANSETCONCURRENT_H
