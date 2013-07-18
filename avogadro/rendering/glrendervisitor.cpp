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

#include "glrendervisitor.h"

#include "spheregeometry.h"
#include "ambientocclusionspheregeometry.h"
#include "cylindergeometry.h"
#include "meshgeometry.h"

namespace Avogadro {
namespace Rendering {

GLRenderVisitor::GLRenderVisitor(const Camera &camera_)
  : m_camera(camera_),
    m_renderPass(NotRendering)
{
}

GLRenderVisitor::~GLRenderVisitor()
{
}

void GLRenderVisitor::visit(Drawable &geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(SphereGeometry &geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(AmbientOcclusionSphereGeometry &geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(CylinderGeometry &geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

void GLRenderVisitor::visit(MeshGeometry &geometry)
{
  if (geometry.renderPass() == m_renderPass)
    geometry.render(m_camera);
}

} // End namespace Rendering
} // End namespace Avogadro
