/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ORBITALS_H
#define AVOGADRO_QTPLUGINS_ORBITALS_H

#include <avogadro/core/basisset.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QFutureWatcher>

#include <memory>

class QAction;
class QDialog;
class QProgressDialog;

namespace Avogadro {

namespace QtGui {
class MeshGenerator;
class GaussianSetConcurrent;
class SlaterSetConcurrent;
} // namespace QtGui

namespace Core {
class BasisSet;
class Cube;
class Mesh;
} // namespace Core

namespace QtPlugins {

/**
 * @brief The Orbital plugin shows a window with a list of orbitals and
 *  .. renders selected orbitals
 */
class OrbitalSettingsDialog;
class OrbitalWidget;

class Orbitals : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Orbitals(QObject* parent = nullptr);
  ~Orbitals() override;

  QString name() const override { return tr("Orbital Window"); }
  QString description() const override { return tr("Display orbital lists."); }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

  enum CalcState
  {
    NotStarted = 0,
    Running,
    Completed,
    Canceled
  };

  struct calcInfo
  {
    /// The published cube, once Completed. Weak, so the queue never keeps a
    /// cube alive after the molecule has dropped it; cubeIndex() finds it.
    std::weak_ptr<const Core::Cube> cube;
    unsigned int orbital = 0;
    Core::BasisSet::ElectronType electronType = Core::BasisSet::Paired;
    double resolution = 0.0;
    double isovalue = 0.0;
    unsigned int priority = 0;
    CalcState state = NotStarted;
  };

public slots:
  void moleculeChanged(unsigned int changes);
  void openDialog();

private slots:
  void loadBasis();
  void loadOrbitals();

  /**
   * Re-render an orbital at a higher resolution
   *
   * @param orbital The orbital to render
   * @param resolution The resolution of the cube
   * @param electronType The electron type (Paired, Alpha, or Beta)
   */
  void calculateOrbitalFromWidget(unsigned int orbital, double resolution,
                                  Core::BasisSet::ElectronType electronType);

  /**
   * Calculate all molecular orbitals at low priority and moderate
   * resolution.
   */
  void precalculateOrbitals();

  /**
   * Add an orbital calculation to the queue. Lower priority values
   * run first. Do not set automatic calculations to priority zero,
   * this is reserved for user requested calculations and will run
   * first, displaying a progress dialog.
   *
   * @param orbital Orbital number
   * @param resolution Resolution of grid
   * @param isoval Isovalue for surface
   * @param electronType The electron type (Paired, Alpha, or Beta)
   * @param priority Priority. Default = 0 (user requested)
   */
  void addCalculationToQueue(unsigned int orbital, double resolution,
                             double isoval,
                             Core::BasisSet::ElectronType electronType,
                             unsigned int priority = 0);
  /**
   * Check that no calculations are currently running and start the
   * highest priority calculation.
   */
  void checkQueue();

  /**
   * Start or resume the calculation at the indicated index of the
   * queue.
   */
  void startCalculation(unsigned int queueIndex);

  void calculateCube();
  void calculateCubeDone();
  void calculatePosMesh();
  void calculatePosMeshDone();
  void calculateNegMesh();
  void calculateNegMeshDone();
  void calculationComplete();
  void meshComplete();

  /**
   * Draw the indicated orbital on the GLWidget
   */
  void renderOrbital(unsigned int orbital,
                     Core::BasisSet::ElectronType electronType);

private:
  /// Which mesh of the pair the generator is working on.
  enum class MeshPhase
  {
    Idle,
    Positive,
    Negative
  };

  /**
   * @return The index of @p cube among the molecule's cubes, or -1 when the
   * molecule no longer holds it.
   */
  int cubeIndex(const std::weak_ptr<const Core::Cube>& cube) const;

  /**
   * @return Whether @p info has a cube the molecule still holds. A Completed
   * entry whose cube is gone is marked Canceled, to be calculated again.
   */
  bool hasLiveCube(calcInfo& info) const;

  /**
   * Stop the cube and mesh calculations this plugin started, wait for their
   * workers, and drop their unpublished results.
   */
  void stopCalculations();

  /// @return Whether the mesh generator is still writing a mesh.
  bool meshGeneratorBusy() const;

  QAction* m_action;

  QtGui::Molecule* m_molecule = nullptr;
  Core::BasisSet* m_basis = nullptr;

  QList<calcInfo> m_queue;
  int m_currentRunningCalculation = -1;
  bool m_runningCube = false;
  int m_currentMeshCalculation = -1;
  int m_nextMeshCalculation = -1;

  QtGui::GaussianSetConcurrent* m_gaussianConcurrent = nullptr;
  QtGui::SlaterSetConcurrent* m_slaterConcurrent = nullptr;

  QFutureWatcher<void> m_displayMeshWatcher;
  QtGui::MeshGenerator* m_meshGenerator = nullptr;

  // Results are built in objects owned here and handed to the molecule only
  // when complete, so the renderer and any copy of the molecule never see a
  // half-filled cube or one mesh of a pair.
  /// The cube being calculated, until calculateCubeDone() publishes it.
  std::unique_ptr<Core::Cube> m_pendingCube;
  /// Keeps the mesh generator's input alive for the length of the job.
  std::shared_ptr<const Core::Cube> m_meshCube;
  std::unique_ptr<Core::Mesh> m_pendingPosMesh;
  std::unique_ptr<Core::Mesh> m_pendingNegMesh;
  MeshPhase m_meshPhase = MeshPhase::Idle;

  int m_smoothingPasses = 1;
  int m_meshesLeft = 0;
  bool m_updateMesh = false;

  OrbitalWidget* m_dialog = nullptr;
  // OrbitalSettingsDialog* m_orbitalSettingsDialog = nullptr;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_ORBITALS_H
