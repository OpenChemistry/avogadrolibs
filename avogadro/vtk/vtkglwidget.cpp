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
#include <vtkRenderer.h>
#include <vtkLookupTable.h>
#include <vtkRenderViewBase.h>
#include <vtkVolume.h>
#include <QVTKInteractor.h>
#include <vtkInteractorStyleTrackballCamera.h>
#include <vtkRenderer.h>
#include <vtkGenericOpenGLRenderWindow.h>
#include <vtkImageData.h>
#include <vtkImageShiftScale.h>
#include <vtkSmartVolumeMapper.h>
#include <vtkPiecewiseFunction.h>
#include <vtkColorTransferFunction.h>
#include <vtkVolumeProperty.h>

#include <vtkSphereSource.h>
#include <vtkPolyDataMapper.h>

#include <QDebug>

namespace Avogadro {
namespace VTK {

vtkVolume * cubeVolume(Core::Cube *cube)
{
  qDebug() << "Cube dimensions: " << cube->dimensions().x()
           << cube->dimensions().y() << cube->dimensions().z();

  qDebug() << "min/max:" << cube->minValue() << cube->maxValue();
  qDebug() << cube->data()->size();

  vtkNew<vtkImageData> data;
 // data->SetNumberOfScalarComponents(1, nullptr);
  Eigen::Vector3i dim = cube->dimensions();
  data->SetExtent(0, dim.x()-1, 0, dim.y()-1, 0, dim.z()-1);

  data->SetOrigin(cube->min().x(), cube->min().y(), cube->min().z());
  data->SetSpacing(cube->spacing().data());

  data->AllocateScalars(VTK_DOUBLE, 1);

  double *dataPtr = static_cast<double *>(data->GetScalarPointer());
  std::vector<double> *cubePtr = cube->data();

  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k) {
        dataPtr[(k * dim.y() + j) * dim.x() + i] =
            (*cubePtr)[(i * dim.y() + j) * dim.z() + k];
      }

  double range[2];
  range[0] = data->GetScalarRange()[0];
  range[1] = data->GetScalarRange()[1];
// a->GetRange(range);
  qDebug() << "ImageData range: " << range[0] << range[1];

  vtkNew<vtkImageShiftScale> t;
  t->SetInputData(data.GetPointer());
  t->SetShift(-range[0]);
  double magnitude = range[1] - range[0];
  if(magnitude == 0.0)
    {
    magnitude = 1.0;
    }
  t->SetScale(255.0 / magnitude);
  t->SetOutputScalarTypeToDouble();

  qDebug() << "magnitude: " << magnitude;

  t->Update();

  vtkNew<vtkSmartVolumeMapper> volumeMapper;
  vtkNew<vtkVolumeProperty> volumeProperty;
  vtkVolume *volume = vtkVolume::New();

  volumeMapper->SetBlendModeToComposite();
// volumeMapper->SetBlendModeToComposite(); // composite first
  volumeMapper->SetInputConnection(t->GetOutputPort());

  volumeProperty->ShadeOff();
  volumeProperty->SetInterpolationTypeToLinear();

  vtkNew<vtkPiecewiseFunction> compositeOpacity;
  vtkNew<vtkColorTransferFunction> color;
  //if (cube->cubeType() == Core::Cube::MO) {
    compositeOpacity->AddPoint( 0.00, 0.6);
    compositeOpacity->AddPoint( 63.75, 0.7);
    compositeOpacity->AddPoint(127.50, 0.0);
    compositeOpacity->AddPoint(192.25, 0.7);
    compositeOpacity->AddPoint(255.00, 0.6);

    color->AddRGBPoint(  0.00, 1.0, 0.0, 0.0);
    color->AddRGBPoint( 63.75, 0.8, 0.0, 0.0);
    color->AddRGBPoint(127.50, 0.0, 0.1, 0.0);
    color->AddRGBPoint(192.25, 0.0, 0.0, 0.8);
    color->AddRGBPoint(255.00, 0.0, 0.0, 1.0);
  //}
//  else {
//    compositeOpacity->AddPoint( 0.00, 0.00);
//    compositeOpacity->AddPoint( 1.75, 0.30);
//    compositeOpacity->AddPoint( 2.50, 0.50);
//    compositeOpacity->AddPoint(192.25, 0.85);
//    compositeOpacity->AddPoint(255.00, 0.90);

//    color->AddRGBPoint(  0.00, 0.0, 0.0, 1.0);
//    color->AddRGBPoint( 63.75, 0.0, 0.0, 0.8);
//    color->AddRGBPoint(127.50, 0.0, 0.0, 0.5);
//    color->AddRGBPoint(191.25, 0.0, 0.0, 0.2);
//    color->AddRGBPoint(255.00, 0.0, 0.0, 0.0);
//  }

  volumeProperty->SetScalarOpacity(compositeOpacity.GetPointer()); // composite first.
  volumeProperty->SetColor(color.GetPointer());

  volume->SetMapper(volumeMapper.GetPointer());
  volume->SetProperty(volumeProperty.GetPointer());

  return volume;
}

vtkGLWidget::vtkGLWidget(QWidget* p, const QGLWidget* shareWidget,
                         Qt::WindowFlags f)
  : QVTKWidget2(p, shareWidget, f),
    m_activeTool(nullptr),
    m_defaultTool(nullptr)
{
  setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins,
          SIGNAL(pluginStateChanged(Avogadro::QtGui::ScenePlugin*)),
          SLOT(updateScene()));

  // Set up our renderer, window, scene, etc.
  GetRenderWindow()->AddRenderer(m_vtkRenderer.Get());
  vtkNew<vtkInteractorStyleTrackballCamera> interactor;
  GetInteractor()->SetInteractorStyle(interactor.Get());
  GetInteractor()->Initialize();

  m_actor->setScene(&this->renderer().scene());
  m_vtkRenderer->AddActor(m_actor.Get());

  //GetRenderWindow()->SetSwapBuffers(0);
  //setAutoBufferSwap(true);
}

vtkGLWidget::~vtkGLWidget()
{
}

void vtkGLWidget::setMolecule(QtGui::Molecule *mol)
{
  clearScene();
  if (m_molecule)
    disconnect(m_molecule, 0, 0, 0);
  m_molecule = mol;
  foreach (QtGui::ToolPlugin *tool, m_tools)
    tool->setMolecule(m_molecule);
  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateScene()));
  if (mol->cubeCount() > 0) {
    vtkVolume* vol = cubeVolume(mol->cube(0));
    m_vtkRenderer->AddViewProp(vol);
  }
}

QtGui::Molecule * vtkGLWidget::molecule()
{
  return m_molecule;
}

const QtGui::Molecule * vtkGLWidget::molecule() const
{
  return m_molecule;
}

void vtkGLWidget::updateScene()
{
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  QtGui::Molecule *mol = m_molecule;
  if (!mol)
    mol = new QtGui::Molecule(this);
  if (mol) {
    Rendering::GroupNode &node = m_renderer.scene().rootNode();
    node.clear();
    Rendering::GroupNode *moleculeNode = new Rendering::GroupNode(&node);

    foreach (QtGui::ScenePlugin *scenePlugin,
             m_scenePlugins.activeScenePlugins()) {
      Rendering::GroupNode *engineNode = new Rendering::GroupNode(moleculeNode);
      scenePlugin->process(*mol, *engineNode);
    }

    // Let the tools perform any drawing they need to do.
    if (m_activeTool) {
      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
      m_activeTool->draw(*toolNode);
    }

    if (m_defaultTool) {
      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
      m_defaultTool->draw(*toolNode);
    }

    m_renderer.resetGeometry();
    updateGL();
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
  updateGL();
}

void vtkGLWidget::resetGeometry()
{
  m_renderer.resetGeometry();
}

}
}
