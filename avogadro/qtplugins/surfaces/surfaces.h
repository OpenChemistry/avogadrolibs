/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SURFACES_H
#define AVOGADRO_QTPLUGINS_SURFACES_H

#include <avogadro/qtgui/extensionplugin.h>

#include <tinycolormap.hpp>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/color3f.h>

#include <QtCore/QFutureWatcher>
#include <QtCore/QPointer>

#include <memory>
#include <vector>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtGui {
class MeshGenerator;
class GaussianSetConcurrent;
class SlaterSetConcurrent;
class TimedProgressDialog;
} // namespace QtGui

namespace Core {
class BasisSet;
class Cube;
class Mesh;
} // namespace Core

namespace QtPlugins {

/**
 * @brief The Surfaces plugin registers quantum file formats, adds several
 * menu entries to calculate surfaces, including QM ones.
 */

class SurfaceDialog;

class Surfaces : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Surfaces(QObject* parent = nullptr);
  ~Surfaces() override;

  enum Type
  {
    VanDerWaals,
    SolventAccessible,
    SolventExcluded,
    ElectrostaticPotential,
    ElectronDensity,
    MolecularOrbital,
    SpinDensity,
    FromFile,
    Unknown
  };

  enum ColorProperty
  {
    None,
    ByElectrostaticPotential
  };

  QString name() const override { return tr("Surfaces"); }
  QString description() const override
  {
    return tr("Read and render surfaces.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

  void registerCommands() override;

public slots:
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;
  void moleculeChanged(unsigned int changes);

private slots:
  void surfacesActivated();
  void calculateSurface();
  void calculateEDT(Type type = Unknown, float defaultResolution = 0.0);
  void performEDTStep(); // EDT step for SolventExcluded
  void edtFinished();
  void calculateQM(Type type = Unknown, int index = -1, bool betaSpin = false,
                   float isoValue = 0.0, float defaultResolution = 0.0);
  void calculateCube(int index = -1, float isoValue = 0.0);
  void qmFinished();

  void stepChanged(int);

  void displayMesh();
  void meshFinished();

  void recordMovie();
  void movieFrame();

private:
  /// What is filling m_pendingCube.
  enum class CubeProducer
  {
    None,
    EDT,
    Gaussian,
    Slater
  };

  /**
   * Stop the calculations this plugin started, drop their unpublished
   * results, and discard the cubes and meshes on the molecule.
   * @return Whether a cube or mesh calculation was still in progress.
   */
  bool clearSurfaceData();

  /// Wait for this plugin's own workers, which write into m_pendingCube and
  /// the pending meshes, without touching the molecule.
  void waitForOwnWorkers();

  /// Mark the calculations in progress as belonging to a molecule state that
  /// no longer exists, so their results are discarded rather than published.
  void markPendingStale();

  /// Hand the finished m_pendingCube to the molecule and start meshing it,
  /// or report an interruption when it was cancelled or went stale.
  void publishCube(bool canceled);

  /// Publish @p mesh at @p index, or append it and update @p index when
  /// that slot no longer exists.
  void publishMesh(int& index, std::unique_ptr<Core::Mesh> mesh);

  /// A calculation stopped before its surface was published: re-enable the
  /// dialog, stop a movie, and fail a waiting command.
  void reportInterrupted();

  /// Switch the MO set step; @return whether a calculation was interrupted.
  bool changeStep(int step);

  void colorMesh(Core::Mesh& mesh);
  void colorMeshByPotential(Core::Mesh& mesh);

  /**
   * The grid resolution to use. An explicit @p specified value, or the
   * dialog's manual value, is returned unchanged. Otherwise the automatic
   * resolution is chosen, limited by SurfaceVoxelBudget for a grid padded
   * by @p padding Angstrom around the atoms.
   */
  float resolution(float specified = 0.0, double padding = 0.0);
  Core::Color3f chargeGradient(double value, double clamp,
                               tinycolormap::ColormapType colormap) const;
  tinycolormap::ColormapType getColormapFromString(const QString& name) const;

  QList<QAction*> m_actions;
  // Parented to parent() when that is a widget, which may delete it first.
  QPointer<QtGui::TimedProgressDialog> m_progressDialog;

  QtGui::Molecule* m_molecule = nullptr;
  Core::BasisSet* m_basis = nullptr;

  QtGui::GaussianSetConcurrent* m_gaussianConcurrent = nullptr;
  QtGui::SlaterSetConcurrent* m_slaterConcurrent = nullptr;

  // Calculations build their results in objects this plugin owns and hand
  // them to the molecule only when complete (publishCube(), meshFinished()),
  // so neither the renderer nor a copy of the molecule sees a half-filled
  // cube or mesh. Published objects are referred to by index.

  /// Index of the molecule's cube being shown, -1 for none.
  int m_cubeIndex = -1;
  /// The number of cubes, read from the file, that renderCube and the dialog
  /// offer: the molecule's cubes when they were last refreshed.
  Index m_fileCubeCount = 0;
  std::vector<int> m_fileCubeRows; // molecule cube index of each dialog row

  /// The cube being calculated, until publishCube() hands it over.
  std::unique_ptr<Core::Cube> m_pendingCube;
  CubeProducer m_cubeProducer = CubeProducer::None;
  bool m_cubeJobStale = false;

  /* One QFutureWatcher per asynchronous slot function, e.g.:*/
  /* calculateEDT() -> [performEDTStep()] -> edtFinished() */
  QFutureWatcher<void> m_performEDTStepWatcher;
  QFutureWatcher<void> m_displayMeshWatcher;

  /* displayMesh() -> meshFinished() */
  /// Keeps the generators' input cube alive for the length of the job.
  std::shared_ptr<const Core::Cube> m_meshCube;
  /// The meshes being generated, published together by meshFinished().
  std::unique_ptr<Core::Mesh> m_pendingMesh1;
  std::unique_ptr<Core::Mesh> m_pendingMesh2;
  bool m_meshJobStale = false;
  /// Indices of the published meshes, -1 for none.
  int m_mesh1Index = -1;
  int m_mesh2Index = -1;
  QtGui::MeshGenerator* m_meshGenerator1 = nullptr;
  QtGui::MeshGenerator* m_meshGenerator2 = nullptr;

  float m_isoValue = 0.025;
  int m_smoothingPasses = 2;

  /// Resolution used by the command currently running, reported back to the
  /// caller because resolution() picks one when the caller does not.
  float m_commandResolution = 0.0f;
  /// Grid resolution calculateEDT() built its cube with, for the solvent-
  /// excluded erosion step in performEDTStep().
  float m_edtResolution = 0.0f;
  /// True while a script command is waiting on a calculation to finish, so
  /// that an interrupted calculation can report failure rather than leave
  /// the caller waiting for a commandFinished() that will never come.
  bool m_commandPending = false;

  bool m_recordingMovie = false;
  int m_currentFrame = 0;
  int m_frameCount = 1;
  QString m_baseFileName;
  int m_numberLength = 1;

  SurfaceDialog* m_dialog = nullptr;

  class PIMPL;
  PIMPL* d = nullptr;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_SURFACES_H
