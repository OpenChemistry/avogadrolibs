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

#include "geometrynode.h"
#include "glrendervisitor.h"
#include "shader.h"
#include "shaderprogram.h"
#include "textlabel2d.h"
#include "textlabel3d.h"
#include "textrenderstrategy.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>

#include <iostream>

namespace Avogadro {
namespace Rendering {

using Core::Array;

GLRenderer::GLRenderer()
  : m_valid(false), m_textRenderStrategy(nullptr), m_center(Vector3f::Zero()),
    m_radius(20.0)
{
  m_overlayCamera.setIdentity();
}

GLRenderer::~GLRenderer()
{
  delete m_textRenderStrategy;
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
}

void GLRenderer::resize(int width, int height)
{
  if (!m_valid)
    return;

  glViewport(0, 0, static_cast<GLint>(width), static_cast<GLint>(height));
  m_camera.setViewport(width, height);
  m_overlayCamera.setViewport(width, height);
}

void GLRenderer::render()
{
  if (!m_valid)
    return;

  Vector4ub c = m_scene.backgroundColor();
  glClearColor(c[0] / 255.0f, c[1] / 255.0f, c[2] / 255.0f, c[3] / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  applyProjection();

  GLRenderVisitor visitor(m_camera, m_textRenderStrategy);
  // Setup for opaque geometry
  visitor.setRenderPass(OpaquePass);
  glEnable(GL_DEPTH_TEST);
  glDisable(GL_BLEND);
  m_scene.rootNode().accept(visitor);

  // Setup for transparent geometry
  visitor.setRenderPass(TranslucentPass);
  glEnable(GL_BLEND);
  // nvidia drivers have a bug where they don't like blending
  //  so on Mac we can use this (they don't use nvidia)
#ifdef __APPLE__
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
#else
  // Thanks to Giuseppe D'Angelo for a related comment:
  // https://bugreports.qt.io/browse/QTBUG-36739
  glBlendFuncSeparate(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA, GL_ONE, GL_ONE);
#endif
  m_scene.rootNode().accept(visitor);

  // Setup for 3d overlay rendering
  visitor.setRenderPass(Overlay3DPass);
  glClear(GL_DEPTH_BUFFER_BIT);
  m_scene.rootNode().accept(visitor);

  // Setup for 2d overlay rendering
  visitor.setRenderPass(Overlay2DPass);
  visitor.setCamera(m_overlayCamera);
  glDisable(GL_DEPTH_TEST);
  m_scene.rootNode().accept(visitor);
}

void GLRenderer::resetCamera()
{
  resetGeometry();
  m_camera.setIdentity();
  m_camera.translate(-m_center);
  m_camera.preTranslate(-2.22f * m_radius * Vector3f::UnitZ());
}

void GLRenderer::resetGeometry()
{
  m_scene.setDirty(true);
  m_center = m_scene.center();
  m_radius = m_scene.radius();
}

void GLRenderer::setTextRenderStrategy(TextRenderStrategy* tren)
{
  if (tren != m_textRenderStrategy) {
    // Force all labels to be regenerated on the next render:
    class ResetTextLabelVisitor : public Visitor
    {
    public:
      void visit(Node&) override { return; }
      void visit(GroupNode&) override { return; }
      void visit(GeometryNode&) override { return; }
      void visit(Drawable&) override { return; }
      void visit(SphereGeometry&) override { return; }
      void visit(AmbientOcclusionSphereGeometry&) override { return; }
      void visit(CurveGeometry&) override { return; }
      void visit(CylinderGeometry&) override { return; }
      void visit(MeshGeometry&) override { return; }
      void visit(Texture2D&) { return; }
      void visit(TextLabel2D& l) override { l.resetTexture(); }
      void visit(TextLabel3D& l) override { l.resetTexture(); }
      void visit(LineStripGeometry&) override { return; }
    } labelResetter;

    m_scene.rootNode().accept(labelResetter);

    delete m_textRenderStrategy;
    m_textRenderStrategy = tren;
  }
}

void GLRenderer::applyProjection()
{
  float distance = m_camera.distance(m_center);
  if (m_camera.projectionType() == Perspective) {
    m_camera.calculatePerspective(40.0f, std::max(2.0f, distance - m_radius),
                                  distance + m_radius);
  } else {
    // Renders the orthographic projection of the molecule
    const double halfHeight = m_radius;
    const double halfWidth = halfHeight * m_camera.width() / m_camera.height();
    m_camera.calculateOrthographic(
      -halfWidth, halfWidth, -halfHeight, halfHeight,
      std::max(2.0f, distance - m_radius), distance + m_radius);
  }
  m_overlayCamera.calculateOrthographic(
    0.f, static_cast<float>(m_overlayCamera.width()), 0.f,
    static_cast<float>(m_overlayCamera.height()), -1.f, 1.f);
}

std::multimap<float, Identifier> GLRenderer::hits(
  const GroupNode* group, const Vector3f& rayOrigin, const Vector3f& rayEnd,
  const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> result;
  if (!group)
    return result;

  for (auto it = group->children().begin(); it != group->children().end();
       ++it) {
    std::multimap<float, Identifier> loopHits;
    const Node* itNode = it->node;
    const GroupNode* childGroup = dynamic_cast<const GroupNode*>(itNode);
    if (childGroup) {
      loopHits = hits(childGroup, rayOrigin, rayEnd, rayDirection);
      result.insert(loopHits.begin(), loopHits.end());
      continue;
    }
    const GeometryNode* childGeometry = itNode->cast<GeometryNode>();
    if (childGeometry) {
      loopHits = hits(childGeometry, rayOrigin, rayEnd, rayDirection);
      result.insert(loopHits.begin(), loopHits.end());
      continue;
    }
  }
  return result;
}

std::multimap<float, Identifier> GLRenderer::hits(
  const GeometryNode* geometry, const Vector3f& rayOrigin,
  const Vector3f& rayEnd, const Vector3f& rayDirection) const
{
  if (!geometry)
    return std::multimap<float, Identifier>();
  return geometry->hits(rayOrigin, rayEnd, rayDirection);
}

std::multimap<float, Identifier> GLRenderer::hits(int x, int y) const
{
  // Our ray:
  const Vector3f origin(m_camera.unProject(
    Vector3f(static_cast<float>(x), static_cast<float>(y), 0.f)));
  const Vector3f end(m_camera.unProject(
    Vector3f(static_cast<float>(x), static_cast<float>(y), 1.f)));
  const Vector3f direction((end - origin).normalized());

  return hits(&m_scene.rootNode(), origin, end, direction);
}

Array<Identifier> GLRenderer::hits(const GroupNode* group,
                                   const Frustrum& f) const
{
  Array<Identifier> result;

  for (auto it = group->children().begin(); it != group->children().end();
       ++it) {
    Array<Identifier> loopHits;
    const Node* itNode = it->node;
    const GroupNode* childGroup = dynamic_cast<const GroupNode*>(itNode);
    if (childGroup) {
      loopHits = hits(childGroup, f);
      result.insert(result.end(), loopHits.begin(), loopHits.end());
      continue;
    }
    const auto childGeometry = itNode->cast<GeometryNode>();
    if (childGeometry) {
      loopHits = childGeometry->areaHits(f);
      result.insert(result.end(), loopHits.begin(), loopHits.end());
      continue;
    }
  }

  return result;
}

Array<Identifier> GLRenderer::hits(int x1, int y1, int x2, int y2) const
{
  // Figure out where the corners of our rectangle are.
  Frustrum f;
  f.points[0] = m_camera.unProject(
    Vector3f(static_cast<float>(x1), static_cast<float>(y1), 0.f));
  f.points[1] = m_camera.unProject(
    Vector3f(static_cast<float>(x1), static_cast<float>(y1), 1.f));
  f.points[2] = m_camera.unProject(
    Vector3f(static_cast<float>(x1), static_cast<float>(y2), 0.f));
  f.points[3] = m_camera.unProject(
    Vector3f(static_cast<float>(x1), static_cast<float>(y2), 1.f));
  f.points[4] = m_camera.unProject(
    Vector3f(static_cast<float>(x2), static_cast<float>(y2), 0.f));
  f.points[5] = m_camera.unProject(
    Vector3f(static_cast<float>(x2), static_cast<float>(y2), 1.f));
  f.points[6] = m_camera.unProject(
    Vector3f(static_cast<float>(x2), static_cast<float>(y1), 0.f));
  f.points[7] = m_camera.unProject(
    Vector3f(static_cast<float>(x2), static_cast<float>(y1), 1.f));

  // Define a frustrum for testing if things are within it.
  f.planes[0] = (f.points[0] - f.points[1]).cross(f.points[2] - f.points[3]);
  f.planes[1] = (f.points[2] - f.points[3]).cross(f.points[4] - f.points[5]);
  f.planes[2] = (f.points[4] - f.points[5]).cross(f.points[6] - f.points[7]);
  f.planes[3] = (f.points[6] - f.points[7]).cross(f.points[0] - f.points[1]);

  return hits(&m_scene.rootNode(), f);
}

} // namespace Rendering
} // namespace Avogadro
