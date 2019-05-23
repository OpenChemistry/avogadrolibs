/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "vtkglwidget.h"

#include <avogadro/core/cube.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>

#include "vtkAvogadroActor.h"
#include <QVTKInteractor.h>
#include <vtkColorTransferFunction.h>
#include <vtkFlyingEdges3D.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkImageData.h>
#include <vtkImageShiftScale.h>
#include <vtkInteractorStyleTrackballCamera.h>
#include <vtkLookupTable.h>
#include <vtkMolecule.h>
#include <vtkMoleculeMapper.h>
#include <vtkPiecewiseFunction.h>
#include <vtkPolyDataMapper.h>
#include <vtkProperty.h>
#include <vtkRenderViewBase.h>
#include <vtkRenderer.h>
#include <vtkSmartVolumeMapper.h>
#include <vtkVolume.h>
#include <vtkVolumeProperty.h>

#include <QtGui/QSurfaceFormat>

namespace Avogadro {
namespace VTK {

using QtGui::Molecule;

// The caller assumes ownership of the vtkImageData returned.
vtkImageData* createCubeImageData(Core::Cube* cube)
{
  auto data = vtkImageData::New();
  // data->SetNumberOfScalarComponents(1, nullptr);
  Eigen::Vector3i dim = cube->dimensions();
  data->SetExtent(0, dim.x() - 1, 0, dim.y() - 1, 0, dim.z() - 1);

  data->SetOrigin(cube->min().x(), cube->min().y(), cube->min().z());
  data->SetSpacing(cube->spacing().data());

  data->AllocateScalars(VTK_DOUBLE, 1);

  double* dataPtr = static_cast<double*>(data->GetScalarPointer());
  std::vector<double>* cubePtr = cube->data();

  for (int i = 0; i < dim.x(); ++i) {
    for (int j = 0; j < dim.y(); ++j) {
      for (int k = 0; k < dim.z(); ++k) {
        dataPtr[(k * dim.y() + j) * dim.x() + i] =
          (*cubePtr)[(i * dim.y() + j) * dim.z() + k];
      }
    }
  }

  return data;
}

void vtkGLWidget::cubeVolume(Core::Cube* cube)
{
  m_imageData = createCubeImageData(cube);
  // Call delete to decrement the reference count now it is in a smart pointer.
  m_imageData->Delete();

  vtkNew<vtkSmartVolumeMapper> volumeMapper;
  vtkNew<vtkVolumeProperty> volumeProperty;

  volumeMapper->SetBlendModeToComposite();
  volumeMapper->SetInputData(m_imageData);
  // volumeMapper->SetInputConnection(t->GetOutputPort());

  volumeProperty->ShadeOff();
  volumeProperty->SetInterpolationTypeToLinear();

  auto compositeOpacity = m_opacityFunction.Get();
  auto color = m_lut.Get();
  if (color->GetSize() == 0) {
    // Initialize the color and opacity function.
    double range[2];
    m_imageData->GetScalarRange(range);
    if (range[0] < 0.0) {
      // Likely a molecular orbital, let's make something symmetric.
      auto magnitude = std::max(std::fabs(range[0]), std::fabs(range[1]));
      color->AddRGBPoint(-magnitude, 1.0, 0.0, 0.0);
      color->AddRGBPoint(-0.01 * magnitude, 1.0, 0.0, 0.0);
      color->AddRGBPoint(0.01 * magnitude, 0.0, 0.0, 1.0);
      color->AddRGBPoint(magnitude, 0.0, 0.0, 1.0);

      compositeOpacity->AddPoint(-magnitude, 1.0);
      compositeOpacity->AddPoint(-0.2 * magnitude, 0.8);
      compositeOpacity->AddPoint(0, 0.0);
      compositeOpacity->AddPoint(0.2 * magnitude, 0.8);
      compositeOpacity->AddPoint(magnitude, 1.0);
    }
  }

  volumeProperty->SetScalarOpacity(compositeOpacity); // composite first.
  volumeProperty->SetColor(color);

  m_volume->SetMapper(volumeMapper);
  m_volume->SetProperty(volumeProperty);
}

vtkGLWidget::vtkGLWidget(QWidget* p, Qt::WindowFlags f)
  : QVTKOpenGLWidget(p, f), m_activeTool(nullptr), m_defaultTool(nullptr)
{
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins,
          SIGNAL(pluginStateChanged(Avogadro::QtGui::ScenePlugin*)),
          SLOT(updateScene()));

  // Set up our renderer, window, scene, etc.
  vtkNew<vtkGenericOpenGLRenderWindow> renderWindow;
  SetRenderWindow(renderWindow);
  GetRenderWindow()->AddRenderer(m_vtkRenderer);
  setFormat(QVTKOpenGLWidget::defaultFormat());
  vtkNew<vtkInteractorStyleTrackballCamera> interactor;
  GetInteractor()->SetInteractorStyle(interactor);
  GetInteractor()->Initialize();
  m_vtkRenderer->SetBackground(1.0, 1.0, 1.0);

  // m_actor->setScene(&this->renderer().scene());
  m_moleculeMapper->UseBallAndStickSettings();
  m_actor->SetMapper(m_moleculeMapper);
  m_actor->GetProperty()->SetAmbient(0.0);
  m_actor->GetProperty()->SetDiffuse(1.0);
  m_actor->GetProperty()->SetSpecular(0.0);
  m_actor->GetProperty()->SetSpecularPower(40);
  m_vtkRenderer->AddActor(m_actor);
  m_vtkRenderer->AddViewProp(m_volume);

  // Set up the flying edges contour pipeline.
  m_contourMapper->SetInputConnection(m_flyingEdges->GetOutputPort());
  m_contourActor->GetProperty()->SetOpacity(0.5);
  m_contourActor->SetMapper(m_contourMapper);
  m_vtkRenderer->AddActor(m_contourActor);
  m_contourActor->SetVisibility(0);
}

vtkGLWidget::~vtkGLWidget() {}

void vtkGLWidget::setMolecule(QtGui::Molecule* mol)
{
  clearScene();
  if (m_molecule)
    disconnect(m_molecule, 0, 0, 0);
  m_molecule = mol;
  foreach (QtGui::ToolPlugin* tool, m_tools)
    tool->setMolecule(m_molecule);
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateScene()));
  connect(m_molecule, SIGNAL(changed(unsigned int)),
          SLOT(moleculeChanged(unsigned int)));

  updateCube();
  // Reset the camera, re-render.
  m_vtkRenderer->ResetCamera();
  GetRenderWindow()->Render();
}

void vtkGLWidget::updateCube()
{
  auto mol = m_molecule;
  if (mol->cubeCount() > 0) {
    // Convert the cube to a vtkImageData for volume rendering/contouring.
    cubeVolume(mol->cube(0));

    // Set up a connection for the contour filter too.
    m_flyingEdges->SetInputData(m_imageData);
    m_flyingEdges->GenerateValues(2, -0.05, 0.05);
    m_flyingEdges->ComputeNormalsOn();
    m_flyingEdges->ComputeScalarsOn();
    m_flyingEdges->SetArrayComponent(0);
    m_contourMapper->SetLookupTable(m_lut);
    m_contourMapper->SetScalarRange(m_imageData->GetScalarRange());
    emit imageDataUpdated();
  }
}

void vtkGLWidget::moleculeChanged(unsigned int c)
{
  Q_ASSERT(m_molecule == qobject_cast<Molecule*>(sender()));

  // I think we need to look at adding cubes to changes, flaky right now.
  auto changes = static_cast<Molecule::MoleculeChanges>(c);
  if (changes & Molecule::Added || changes & Molecule::Removed) {
    updateCube();
    GetRenderWindow()->Render();
  }
}

QtGui::Molecule* vtkGLWidget::molecule()
{
  return m_molecule;
}

const QtGui::Molecule* vtkGLWidget::molecule() const
{
  return m_molecule;
}

vtkColorTransferFunction* vtkGLWidget::lut() const
{
  return m_lut;
}

vtkPiecewiseFunction* vtkGLWidget::opacityFunction() const
{
  return m_opacityFunction;
}

vtkImageData* vtkGLWidget::imageData() const
{
  return m_imageData;
}

void vtkGLWidget::renderVolume(bool enable)
{
  m_volume->SetVisibility(enable ? 1 : 0);
}

void vtkGLWidget::renderIsosurface(bool enable)
{
  m_contourActor->SetVisibility(enable ? 1 : 0);
}

void vtkGLWidget::setIsoValue(double value)
{
  m_flyingEdges->SetNumberOfContours(2);
  m_flyingEdges->SetValue(0, -value);
  m_flyingEdges->SetValue(1, value);
}

void vtkGLWidget::setOpacity(double value)
{
  m_contourActor->GetProperty()->SetOpacity(value);
}

void vtkGLWidget::updateScene()
{
  if (m_molecule) {
    if (m_vtkMolecule)
      m_vtkMolecule->Delete();
    m_vtkMolecule = vtkMolecule::New();
    for (Index i = 0; i < m_molecule->atomCount(); ++i) {
      auto a = m_molecule->atom(i);
      m_vtkMolecule->AppendAtom(a.atomicNumber(), a.position3d().x(),
                                a.position3d().y(), a.position3d().z());
    }
    for (Index i = 0; i < m_molecule->bondCount(); ++i) {
      auto b = m_molecule->bond(i);
      m_vtkMolecule->AppendBond(b.atom1().index(), b.atom2().index(),
                                b.order());
    }
    m_moleculeMapper->SetInputData(m_vtkMolecule);
    return;
  }
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  QtGui::Molecule* mol = m_molecule;
  if (!mol)
    mol = new QtGui::Molecule(this);
  if (mol) {
    Rendering::GroupNode& node = m_renderer.scene().rootNode();
    node.clear();
    Rendering::GroupNode* moleculeNode = new Rendering::GroupNode(&node);

    foreach (QtGui::ScenePlugin* scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      Rendering::GroupNode* engineNode = new Rendering::GroupNode(moleculeNode);
      scenePlugin->process(*mol, *engineNode);
    }

    // Let the tools perform any drawing they need to do.
    if (m_activeTool) {
      Rendering::GroupNode* toolNode = new Rendering::GroupNode(moleculeNode);
      m_activeTool->draw(*toolNode);
    }

    if (m_defaultTool) {
      Rendering::GroupNode* toolNode = new Rendering::GroupNode(moleculeNode);
      m_defaultTool->draw(*toolNode);
    }

    m_renderer.resetGeometry();
    update();
  }
  if (mol != m_molecule)
    delete mol;
}

void vtkGLWidget::clearScene()
{
  m_renderer.scene().clear();
}

void vtkGLWidget::resetCamera()
{
  m_renderer.resetCamera();
  update();
}

void vtkGLWidget::resetGeometry()
{
  m_renderer.resetGeometry();
}
} // namespace VTK
} // namespace Avogadro
