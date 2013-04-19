#ifndef GAUSSIANSETCONCURRENT_H
#define GAUSSIANSETCONCURRENT_H

#include <QtCore/QObject>
#include <QtCore/QFuture>
#include <QtCore/QFutureWatcher>

namespace Avogadro {

namespace QtGui {
class Cube;
}
namespace Core {
class Molecule;
class GaussianSet;
class GaussianSetTools;
}

namespace QtPlugins {

struct GaussianShell;

class GaussianSetConcurrent : public QObject
{
  Q_OBJECT

public:
  explicit GaussianSetConcurrent(QObject *p = 0);
  ~GaussianSetConcurrent();

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
  QVector<GaussianShell> *m_gaussianShells;

  Core::GaussianSet *m_set;
  Core::GaussianSetTools *m_tools;

  bool setUpCalculation(QtGui::Cube *cube, unsigned int state,
                        void (*func)(GaussianShell &));

  static void processOrbital(GaussianShell &shell);
  static void processDensity(GaussianShell &shell);
  static void processSpinDensity(GaussianShell &shell);
};

}
}

#endif // GAUSSIANSETCONCURRENT_H
