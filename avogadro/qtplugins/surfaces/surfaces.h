/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SURFACES_H
#define AVOGADRO_QTPLUGINS_SURFACES_H

#include <avogadro/qtgui/extensionplugin.h>

#include "tinycolormap.hpp"

#include <avogadro/core/color3f.h>

#include <QtCore/QFutureWatcher>

class QAction;
class QDialog;
class QProgressDialog;

namespace Avogadro {

namespace QtGui {
class MeshGenerator;
}

namespace Core {
class BasisSet;
class Cube;
class Mesh;
}

namespace QtPlugins {

/**
 * @brief The Surfaces plugin registers quantum file formats, adds several
 * menu entries to calculate surfaces, including QM ones.
 */

class GaussianSetConcurrent;
class SlaterSetConcurrent;
class SurfaceDialog;

class Surfaces : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Surfaces(QObject* parent = nullptr);
  ~Surfaces();

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
  QString description() const override { return tr("Read and render surfaces."); }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void surfacesActivated();
  void calculateSurface();
  void calculateEDT();
  void performEDTStep(); // EDT step for SolventExcluded
  void calculateQM();
  void calculateCube();

  void stepChanged(int);

  void displayMesh();
  void meshFinished();
  
  void colorMesh();
  void colorMeshByPotential();

  void recordMovie();
  void movieFrame();

private:
  float resolution();
  Core::Color3f chargeGradient(
    double value, double clamp, tinycolormap::ColormapType colormap
  ) const;
  tinycolormap::ColormapType getColormapFromString(const QString& name) const;

  QList<QAction*> m_actions;
  QProgressDialog* m_progressDialog = nullptr;

  QtGui::Molecule* m_molecule = nullptr;
  Core::BasisSet* m_basis = nullptr;

  GaussianSetConcurrent* m_gaussianConcurrent = nullptr;
  SlaterSetConcurrent* m_slaterConcurrent = nullptr;

  Core::Cube* m_cube = nullptr;
  std::vector<Core::Cube*> m_cubes;
  /* One QFutureWatcher per asynchronous slot function, e.g.:*/
  /* calculateEDT() -> [performEDTStep()] -> displayMesh() */
  QFutureWatcher<void> m_performEDTStepWatcher;
  QFutureWatcher<void> m_displayMeshWatcher;
  Core::Mesh* m_mesh1 = nullptr;
  Core::Mesh* m_mesh2 = nullptr;
  /* displayMesh() -> meshFinished() */
  QtGui::MeshGenerator* m_meshGenerator1 = nullptr;
  QtGui::MeshGenerator* m_meshGenerator2 = nullptr;

  float m_isoValue = 0.01;
  int m_smoothingPasses = 6;
  int m_meshesLeft = 0;

  bool m_recordingMovie = false;
  int m_currentFrame = 0;
  int m_frameCount = 1;
  QString m_baseFileName;
  int m_numberLength = 1;

  SurfaceDialog* m_dialog = nullptr;

  class PIMPL;
  PIMPL* d = nullptr;
};
}
}

#endif // AVOGADRO_QTPLUGINS_QUANTUMOUTPUT_H
