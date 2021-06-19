/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.
  Copyright 2018 Geoffrey Hutchison

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/
#ifndef AVOGADRO_QTPLUGINS_SURFACES_H
#define AVOGADRO_QTPLUGINS_SURFACES_H

#include <avogadro/qtgui/extensionplugin.h>

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

  QString name() const { return tr("Surfaces"); }
  QString description() const { return tr("Read and render surfaces."); }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void surfacesActivated();
  void calculateSurface();
  void calculateEDT();
  void calculateQM();
  void calculateCube();

  void stepChanged(int);

  void displayMesh();
  void meshFinished();

  void recordMovie();
  void movieFrame();

private:
  QList<QAction*> m_actions;
  QProgressDialog* m_progressDialog = nullptr;

  QtGui::Molecule* m_molecule = nullptr;
  Core::BasisSet* m_basis = nullptr;

  GaussianSetConcurrent* m_gaussianConcurrent = nullptr;
  SlaterSetConcurrent* m_slaterConcurrent = nullptr;

  Core::Cube* m_cube = nullptr;
  std::vector<Core::Cube*> m_cubes;
  Core::Mesh* m_mesh1 = nullptr;
  Core::Mesh* m_mesh2 = nullptr;
  QtGui::MeshGenerator* m_meshGenerator1 = nullptr;
  QtGui::MeshGenerator* m_meshGenerator2 = nullptr;

  float m_isoValue = 0.01;
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
