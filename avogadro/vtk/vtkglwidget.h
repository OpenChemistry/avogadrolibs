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

#include <QVTKOpenGLWidget.h>
#include <vtkNew.h>
#include <vtkSmartPointer.h>

#include <avogadro/qtgui/scenepluginmodel.h>
#include <avogadro/rendering/glrenderer.h>

#include <QtCore/QPointer>

class vtkActor;
class vtkColorTransferFunction;
class vtkFlyingEdges3D;
class vtkMolecule;
class vtkMoleculeMapper;
class vtkPiecewiseFunction;
class vtkPolyDataMapper;
class vtkRenderer;
class vtkVolume;
class vtkImageData;

namespace Avogadro {
namespace Core {
class Cube;
}
namespace QtGui {
class Molecule;
class ToolPlugin;
} // namespace QtGui

namespace VTK {

class AVOGADROVTK_EXPORT vtkGLWidget : public QVTKOpenGLWidget
{
  Q_OBJECT

public:
  vtkGLWidget(QWidget* p = nullptr, Qt::WindowFlags f = Qt::WindowFlags());
  ~vtkGLWidget();

  /** Set the molecule the widget will render. */
  void setMolecule(QtGui::Molecule* molecule);

  /**
   * Get the molecule being rendered by the widget.
   * @{
   */
  QtGui::Molecule* molecule();
  const QtGui::Molecule* molecule() const;
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

  /**
   * Get the color loop up table for the volume renderer.
   */
  vtkColorTransferFunction* lut() const;

  /**
   * Get the opacity function for the volume renderer.
   */
  vtkPiecewiseFunction* opacityFunction() const;

  /**
   * Get the vtkImageData that is being rendered.
   */
  vtkImageData* imageData() const;

  /**
   * Set the cube to render.
   */
  void setCube(Core::Cube* cube);

  /**
   * Get the cube being rendered, this is the input for the imageData.
   */
  Core::Cube* cube();

  /**
   * Display the volume rendering.
   */
  void renderVolume(bool enable);

  /**
   * Display an isosurface.
   */
  void renderIsosurface(bool enable);

  /**
   * Set the isovalue for the isosurface.
   */
  void setIsoValue(double value);

  /**
   * Set the isovalue for the isosurface.
   */
  void setOpacity(double value);

signals:
  /**
   * Emitted if the image data is updated so that histograms etc can update.
   */
  void imageDataUpdated();

public slots:
  /**
   * Update the scene plugins for the widget, this will generate geometry in
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

  /** Volume render the supplied cube. */
  void cubeVolume(Core::Cube* cube);

private slots:
  void moleculeChanged(unsigned int c);

  void updateCube();

private:
  QPointer<QtGui::Molecule> m_molecule;
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin* m_activeTool;
  QtGui::ToolPlugin* m_defaultTool;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;

  // vtkNew<vtkRenderViewBase> m_context;
  vtkNew<vtkRenderer> m_vtkRenderer;

  // The volume rendering pieces.
  vtkNew<vtkColorTransferFunction> m_lut;
  vtkNew<vtkPiecewiseFunction> m_opacityFunction;
  vtkSmartPointer<vtkImageData> m_imageData;
  vtkNew<vtkVolume> m_volume;

  // The contour pieces.
  vtkNew<vtkActor> m_contourActor;
  vtkNew<vtkPolyDataMapper> m_contourMapper;
  vtkNew<vtkFlyingEdges3D> m_flyingEdges;

  // The molecule actor, data structure, mapper.
  vtkNew<vtkActor> m_actor;
  vtkSmartPointer<vtkMolecule> m_vtkMolecule;
  vtkNew<vtkMoleculeMapper> m_moleculeMapper;
};
} // namespace VTK
} // namespace Avogadro

#endif // AVOGADRO_VTKGLWIDGET_H
