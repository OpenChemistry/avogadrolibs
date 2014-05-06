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

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/qtgui/toolplugin.h>

#include "vtkAvogadroActor.h"
#include <vtkRenderer.h>
#include <vtkLookupTable.h>
#include <vtkRenderViewBase.h>
#include <vtkVolume.h>
#include <vtkInteractorStyleTrackballCamera.h>
#include <vtkRenderer.h>
#include <vtkRenderWindow.h>

#include <vtkSphereSource.h>
#include <vtkPolyDataMapper.h>

namespace Avogadro {
namespace VTK {

vtkGLWidget::vtkGLWidget(QWidget* p, Qt::WindowFlags f)
  : QVTKWidget(p, f),
    m_activeTool(NULL),
    m_defaultTool(NULL)
{
  //setFocusPolicy(Qt::ClickFocus);
  connect(&m_scenePlugins,
          SIGNAL(pluginStateChanged(Avogadro::QtGui::ScenePlugin*)),
          SLOT(updateScene()));

  // Set up our renderer, window, scene, etc.
  GetRenderWindow()->AddRenderer(m_vtkRenderer.Get());

  //m_context->SetInteractor(this->GetInteractor());
  //this->SetRenderWindow(m_context->GetRenderWindow());
  vtkNew<vtkInteractorStyleTrackballCamera> interactor;
  GetInteractor()->SetInteractorStyle(interactor.Get());
  GetInteractor()->Initialize();

  m_actor->setScene(&this->renderer().scene());
  m_vtkRenderer->AddActor(m_actor.Get());

  vtkNew<vtkSphereSource> sphere;
  sphere->SetRadius(0.5);
  sphere->SetCenter(0, 0, 0);
  vtkNew<vtkPolyDataMapper> mapper;
  mapper->SetInputConnection(sphere->GetOutputPort());
  vtkNew<vtkActor> sphereActor;
  sphereActor->SetMapper(mapper.Get());
  m_vtkRenderer->AddActor(sphereActor.Get());
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


  return;
  // Build up the scene with the scene plugins, creating the appropriate nodes.
  QtGui::Molecule *mol = m_molecule;
  if (!mol)
    mol = new QtGui::Molecule(this);
//  if (mol) {
//    Rendering::GroupNode &node = m_renderer.scene().rootNode();
//    node.clear();
//    Rendering::GroupNode *moleculeNode = new Rendering::GroupNode(&node);

//    foreach (QtGui::ScenePlugin *scenePlugin,
//             m_scenePlugins.activeScenePlugins()) {
//      Rendering::GroupNode *engineNode = new Rendering::GroupNode(moleculeNode);
//      scenePlugin->process(*mol, *engineNode);
//    }

//    // Let the tools perform any drawing they need to do.
//    if (m_activeTool) {
//      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
//      m_activeTool->draw(*toolNode);
//    }

//    if (m_defaultTool) {
//      Rendering::GroupNode *toolNode = new Rendering::GroupNode(moleculeNode);
//      m_defaultTool->draw(*toolNode);
//    }

  //  m_renderer.resetGeometry();
    update();
//  }
  if (mol != m_molecule)
    delete mol;
}

void vtkGLWidget::clearScene()
{
  //m_renderer.scene().clear();
}

void vtkGLWidget::resetCamera()
{
  //m_renderer.resetCamera();
  update();
}

void vtkGLWidget::resetGeometry()
{
  //m_renderer.resetGeometry();
}

}
}
