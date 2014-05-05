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
#include <QVTKWidget.h>

namespace Avogadro {
namespace VTK {

class AVOGADROVTK_EXPORT vtkGLWidget : public QVTKWidget
{
  Q_OBJECT

public:
  vtkGLWidget(QWidget* p = NULL, Qt::WindowFlags f = 0);
  ~vtkGLWidget();

private:
  QPointer<QtGui::Molecule> m_molecule;
  QList<QtGui::ToolPlugin*> m_tools;
  QtGui::ToolPlugin *m_activeTool;
  QtGui::ToolPlugin *m_defaultTool;
  Rendering::GLRenderer m_renderer;
  QtGui::ScenePluginModel m_scenePlugins;
};

}
}

#endif // AVOGADRO_VTKGLWIDGET_H
