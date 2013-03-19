/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "glrenderer.h"

#include "avogadrogl.h"

#include "shader.h"
#include "shaderprogram.h"
#include "geometrynode.h"

#include <avogadro/core/matrix.h>

#include <iostream>

namespace Avogadro {
namespace Rendering {

GLRenderer::GLRenderer() : m_valid(false)
{
}

GLRenderer::~GLRenderer()
{
}

void GLRenderer::initialize()
{
  GLenum result = glewInit();
  m_valid = (result == GLEW_OK);
  if (!m_valid) {
    m_error += "GLEW could not be initialized.\n";
    return;
  }

  if (!GLEW_VERSION_2_0) {
    m_error += "GL version 2.0 is not supported by your graphics driver.\n";
    m_valid = false;
    return;
  }

  glClearColor(0, 0, 0, 0);

  resetCamera();
}

void GLRenderer::resize(int width, int height)
{
  glViewport(0, 0, static_cast<GLint>(width), static_cast<GLint>(height));
  m_camera.setViewport(width, height);
  float distance = std::max(2.0f, m_camera.distance(Vector3f::Zero()));
  m_camera.calculatePerspective(40,
                                distance - 2.0f * m_radius,
                                distance + 2.0f * m_radius);
}

void GLRenderer::render(GroupNode *group)
{
  if (!group)
    return;
  for (std::vector<Node *>::iterator it = group->children().begin();
       it != group->children().end(); ++it) {
    GroupNode *childGroup = (*it)->cast<GroupNode>();
    if (childGroup) {
      render(childGroup);
      continue;
    }
    GeometryNode *childGeometry = (*it)->cast<GeometryNode>();
    if (childGeometry) {
      render(childGeometry);
      continue;
    }
  }
}

void GLRenderer::render(GeometryNode *geometry)
{
  if (!geometry)
    return;
  geometry->render(m_camera);
}

void GLRenderer::render()
{
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  glEnable(GL_DEPTH_TEST);
  render(&m_scene.rootNode());
  glDisable(GL_DEPTH_TEST);
}

void GLRenderer::resetCamera()
{
  Vector3f center = m_scene.center();
  m_radius = m_scene.radius() + 5.0f;
  m_camera.setIdentity();
  m_camera.translate(-center);
  m_camera.preTranslate(-3.0f * m_radius * Vector3f(0.0f, 0.0f, 1.0f));
  float distance = std::max(2.0f, m_camera.distance(Vector3f::Zero()));
  m_camera.calculatePerspective(40.0f,
                                distance - 2.0f * m_radius,
                                distance + 2.0f * m_radius);
}

std::multimap<float, Identifier>
GLRenderer::hits(const GroupNode *group, const Vector3f &rayOrigin,
                 const Vector3f &rayEnd, const Vector3f &rayDirection) const
{
  std::multimap<float, Identifier> result;
  if (!group)
    return result;

  for (std::vector<Node *>::const_iterator it = group->children().begin();
       it != group->children().end(); ++it) {
    std::multimap<float, Identifier> loopHits;
    const Node *itNode = *it;
    const GroupNode *childGroup = dynamic_cast<const GroupNode *>(itNode);
    if (childGroup) {
      loopHits = hits(childGroup, rayOrigin, rayEnd, rayDirection);
      result.insert(loopHits.begin(), loopHits.end());
      continue;
    }
    const GeometryNode *childGeometry = (*it)->cast<GeometryNode>();
    if (childGeometry) {
      loopHits = hits(childGeometry, rayOrigin, rayEnd, rayDirection);
      result.insert(loopHits.begin(), loopHits.end());
      continue;
    }
  }
  return result;
}

std::multimap<float, Identifier>
GLRenderer::hits(const GeometryNode *geometry, const Vector3f &rayOrigin,
                 const Vector3f &rayEnd, const Vector3f &rayDirection) const
{
  if (!geometry)
    return std::multimap<float, Identifier>();
  return geometry->hits(rayOrigin, rayEnd, rayDirection);
}

std::multimap<float, Identifier> GLRenderer::hits(int x, int y) const
{
  // Our ray:
  const Vector3f origin(m_camera.unProject(Vector3f(x, y, 0)));
  const Vector3f end(m_camera.unProject(Vector3f(x, y, 1)));
  const Vector3f direction((end - origin).normalized());

  return hits(&m_scene.rootNode(), origin, end, direction);
}

} // End Rendering namespace
} // End Avogadro namespace
