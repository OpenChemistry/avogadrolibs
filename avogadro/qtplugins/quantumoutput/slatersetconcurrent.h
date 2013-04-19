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

#include <QtCore/QObject>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>

namespace Avogadro {

namespace QtGui {
class Cube;
}
namespace Core {
class Molecule;
class SlaterSet;
class SlaterSetTools;
}

namespace QtPlugins {

struct SlaterShell;

class SlaterSetConcurrent : public QObject
{
  Q_OBJECT

public:
  explicit SlaterSetConcurrent(QObject *p = 0);
  ~SlaterSetConcurrent();

  void setMolecule(Core::Molecule *mol);

  bool calculateMolecularOrbital(QtGui::Cube *cube, unsigned int state);
  bool calculateElectronDensity(QtGui::Cube *cube);
  bool calculateSpinDensity(QtGui::Cube *cube);

  QFutureWatcher<void> & watcher() { return m_watcher; }

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
  QtGui::Cube *m_cube;                  //! Cube to put the results into (3D grid).
  QVector<SlaterShell> *m_shells;

  Core::SlaterSet *m_set;
  Core::SlaterSetTools *m_tools;

  bool setUpCalculation(QtGui::Cube *cube, unsigned int state,
                        void (*func)(SlaterShell &));

  static void processOrbital(SlaterShell &shell);
  static void processDensity(SlaterShell &shell);
  static void processSpinDensity(SlaterShell &shell);
};

}
}

#endif // AVOGADRO_QTPLUGINS_SLATERSETCONCURRENT_H
