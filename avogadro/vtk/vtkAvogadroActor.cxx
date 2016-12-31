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
  : m_scene(nullptr), m_initialized(false)
{
  for (short i = 0; i < 6; ++i)
    m_bounds[i] = 0.0;
}

vtkAvogadroActor::~vtkAvogadroActor()
{
}

int vtkAvogadroActor::RenderOpaqueGeometry(vtkViewport *)
{
  if (!m_initialized) {
    GLenum result = glewInit();
    if (result != GLEW_OK) {
      cout << "Error, could not initialize GLEW." << endl;
      return 0;
    }
    if (!GLEW_VERSION_2_1) {
      cout << "GL version 2.1 is not supported by your GPU." << endl;
      return 0;
    }
    m_initialized = true;
  }
  if (!m_scene)
    return 0;

  // Figure out the current model view and projection matrices for our camera.
  Camera camera;
  Affine3f mv, proj;
  glGetFloatv(GL_MODELVIEW_MATRIX, mv.matrix().data());
  glGetFloatv(GL_PROJECTION_MATRIX, proj.matrix().data());
  camera.setModelView(mv);
  camera.setProjection(proj);

  // Render the Avogadro scene using the GLRenderVisitor and return.
  GLRenderVisitor visitor(camera);
  visitor.setRenderPass(Avogadro::Rendering::OpaquePass);
  m_scene->rootNode().accept(visitor);

  return 1;
}

int vtkAvogadroActor::RenderTranslucentPolygonalGeometry(vtkViewport *)
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
  visitor.setRenderPass(Avogadro::Rendering::TranslucentPass);
  m_scene->rootNode().accept(visitor);

  return 1;
}

int vtkAvogadroActor::HasTranslucentPolygonalGeometry()
{
  return 1;
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
  m_scene = scene;
}

void vtkAvogadroActor::PrintSelf(ostream &os, vtkIndent indent)
{
  Superclass::PrintSelf(os, indent);
}
