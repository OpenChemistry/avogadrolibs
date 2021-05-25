/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_VTKAVOGADROACTOR_H
#define AVOGADRO_VTKAVOGADROACTOR_H

#include "avogadrovtkexport.h"
#include <vtkActor.h>

namespace Avogadro {
namespace Rendering {
class Scene;
}
}

/**
 * @class vtkAvogadroActor vtkAvogadroActor.h <avogadro/vtk/vtkAvogadroActor.h>
 * @brief Wrap an Avogadro::Rendering::Scene in a vtkActor derived container so
 * that it can be rendered in a standard VTK widget.
 * @author Marcus D. Hanwell
 */

class AVOGADROVTK_EXPORT vtkAvogadroActor : public vtkActor
{
public:
  /** Return a new instance of the vtkAvogadroActor. */
  static vtkAvogadroActor* New();

  /** Required type macro. */
  vtkTypeMacro(vtkAvogadroActor, vtkActor)

    /** Print the state of the object. */
    void PrintSelf(ostream& os, vtkIndent indent);

  /** Render the opaque geometry. */
  int RenderOpaqueGeometry(vtkViewport* viewport);

  /** Render the translucent geometry. */
  int RenderTranslucentPolygonalGeometry(vtkViewport* viewport);

  /** Does the actor have translucent geometry? */
  int HasTranslucentPolygonalGeometry();

  /**
   * Get the bounds for this Actor as (Xmin,Xmax,Ymin,Ymax,Zmin,Zmax). (The
   * method GetBounds(double bounds[6]) is available from the superclass.)
   */
  double* GetBounds();

  /** Set the scene on the actor, the actor assumes ownership of the scene. */
  void setScene(Avogadro::Rendering::Scene* scene);

  /** Get the scene being rendered by the actor. */
  Avogadro::Rendering::Scene* GetScene() { return m_scene; }

protected:
  vtkAvogadroActor();
  ~vtkAvogadroActor();

  Avogadro::Rendering::Scene* m_scene;
  double m_bounds[6];

  bool m_initialized;

private:
  vtkAvogadroActor(const vtkAvogadroActor&); // Not implemented.
  void operator=(const vtkAvogadroActor&);   // Not implemented.
};

#endif // AVOGADRO_VTKAVOGADROACTOR_H
