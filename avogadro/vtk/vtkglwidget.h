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

#ifndef AVOGADRO_VTKGLWIDGET_H
#define AVOGADRO_VTKGLWIDGET_H

#include "avogadrovtkexport.h"
#include <QVTKWidget2.h>
#include <vtkNew.h>
#include <vtkSmartPointer.h>

#include <avogadro/rendering/glrenderer.h>
#include <avogadro/qtgui/scenepluginmodel.h>

#include <QtCore/QPointer>

class vtkAvogadroActor;
class vtkLookupTable;
//class vtkRenderViewBase;
class vtkRenderer;
class vtkVolume;

namespace Avogadro {

namespace QtGui {
class Molecule;
class ToolPlugin;
}

namespace VTK {

class AVOGADROVTK_EXPORT vtkGLWidget : public QVTKWidget2
{
  Q_OBJECT

public:
  vtkGLWidget(QWidget* p = nullptr, const QGLWidget* shareWidget = 0,
              Qt::WindowFlags f = 0);
  ~vtkGLWidget();

  /** Set the molecule the widget will render. */
  void setMolecule(QtGui::Molecule *molecule);

  /**
   * Get the molecule being rendered by the widget.
   * @{
   */
  QtGui::Molecule * molecule();
  const QtGui::Molecule * molecule() const;
  /** @}*/

  /** Get a reference to the renderer for the widget. */
  Rendering::GLRenderer& renderer() { return m_renderer; }

  /**
   * Get the GLWidget's ScenePluginModel, used to add, delete and modify the
   * scene plugin items.
   * @{
   */
  QtGui::ScenePluginModel& sceneModel() { return m_scenePlugins; }
  const QtGui::ScenePluginModel& sceneModel() const { return m_scenePlugins; }
  /** @}*/

public slots:
  /**
   * Update the scene plugins for the widget, this will generate geeometry in
   * the scene etc.
   */
  void updateScene();

  /**
   * Clear the contents of the scene.
   */
  void clearScene();

  /** Reset the view to fit the entire scene. */
  void resetCamera();

  /** Reset the geometry when the molecule etc changes. */
  void resetGeometry();

private:
  QPointer<QtGui::Molecule> m_molecule;
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin *m_activeTool;
  QtGui::ToolPlugin *m_defaultTool;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;

  vtkNew<vtkAvogadroActor> m_actor;
  //vtkNew<vtkRenderViewBase> m_context;
  vtkNew<vtkRenderer> m_vtkRenderer;
  vtkNew<vtkLookupTable> m_lut;
  vtkSmartPointer<vtkVolume> m_volume;
};

}
}

#endif // AVOGADRO_VTKGLWIDGET_H
