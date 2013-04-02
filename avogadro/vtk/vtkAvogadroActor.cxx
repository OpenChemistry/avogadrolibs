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

#include "vtkAvogadroActor.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/scene.h>
#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/glrendervisitor.h>

#include <vtkObjectFactory.h>
#include <vtkViewport.h>

using Eigen::Affine3f;
using Avogadro::Vector3f;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::GLRenderVisitor;

vtkStandardNewMacro(vtkAvogadroActor)

vtkAvogadroActor::vtkAvogadroActor()
  : m_scene(new Avogadro::Rendering::Scene)
{
  for (short i = 0; i < 6; ++i)
    m_bounds[i] = 0.0;
}

vtkAvogadroActor::~vtkAvogadroActor()
{
  delete m_scene;
}

int vtkAvogadroActor::RenderOpaqueGeometry(vtkViewport *)
{
  // Figure out the current model view and projection matrices for our camera.
  Camera camera;
  Affine3f mv, proj;
  glGetFloatv(GL_MODELVIEW_MATRIX, mv.matrix().data());
  glGetFloatv(GL_PROJECTION_MATRIX, proj.matrix().data());
  camera.setModelView(mv);
  camera.setProjection(proj);

  // Render the Avogadro scene using the GLRenderVisitor and return.
  GLRenderVisitor visitor(camera);
  m_scene->rootNode().accept(visitor);

  return 1;
}

int vtkAvogadroActor::RenderTranslucentPolygonalGeometry(vtkViewport *)
{
  return 0;
}

int vtkAvogadroActor::HasTranslucentPolygonalGeometry()
{
  return 0;
}

double * vtkAvogadroActor::GetBounds()
{
  if (!m_scene)
    return m_bounds;

  Vector3f center = m_scene->center();
  float radius = m_scene->radius();
  m_bounds[0] = center[0] - radius;
  m_bounds[1] = center[0] + radius;
  m_bounds[2] = center[1] - radius;
  m_bounds[3] = center[1] + radius;
  m_bounds[4] = center[2] - radius;
  m_bounds[5] = center[2] + radius;

  return m_bounds;
}

void vtkAvogadroActor::setScene(Avogadro::Rendering::Scene *scene)
{
  if (m_scene != scene)
    delete m_scene;
  m_scene = scene;
  Modified();
}

void vtkAvogadroActor::PrintSelf(ostream &os, vtkIndent indent)
{
  Superclass::PrintSelf(os, indent);
}
