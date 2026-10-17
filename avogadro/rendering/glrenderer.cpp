/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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

#include <array>
#include <chrono>
#include <iostream>

namespace Avogadro::Rendering {

using Core::Array;

namespace {
constexpr int TimedSections = 6;
constexpr int TimedSlots = 4;
const char* const SectionNames[TimedSections] = { "solid",     "post",
                                                  "opaque",    "translucent",
                                                  "overlay3d", "overlay2d" };
} // namespace

// Bookkeeping for GLRenderer::setTimingEnabled(). One slot holds the CPU
// timings and the six GL_TIME_ELAPSED queries of a single frame; a ring of
// them lets the GPU finish a frame while the next ones are being issued.
struct GLRenderer::TimingState
{
  using Clock = std::chrono::steady_clock;

  struct Slot
  {
    std::array<GLuint, TimedSections> queries = {};
    std::array<double, TimedSections> cpuMs = {};
    std::uint64_t frame = 0;
    std::uint64_t bytes = 0;
  };

  std::array<Slot, TimedSlots> slots;
  bool queriesCreated = false;
  bool gpuAvailable = false;
  int next = 0;    // slot the next frame is recorded in
  int pending = 0; // frames issued but not yet published
  std::uint64_t frameCounter = 0;

  Slot* current = nullptr;
  int section = -1;
  Clock::time_point sectionStart;
  std::uint64_t bytesAtStart = 0;

  ~TimingState()
  {
    if (!queriesCreated)
      return;
    for (Slot& slot : slots)
      glDeleteQueries(TimedSections, slot.queries.data());
  }

  void createQueries()
  {
    gpuAvailable = GLEW_VERSION_3_3 || GLEW_ARB_timer_query;
    if (gpuAvailable) {
      for (Slot& slot : slots)
        glGenQueries(TimedSections, slot.queries.data());
    }
    queriesCreated = gpuAvailable;
  }

  Slot& oldest() { return slots[(next + TimedSlots - pending) % TimedSlots]; }

  void publish(const Slot& slot, bool withGpu, RenderTimings& out) const
  {
    out.frame = slot.frame;
    out.bufferBytesUploaded = slot.bytes;
    out.gpuTimingAvailable = withGpu;
    out.passes.resize(TimedSections);
    for (int i = 0; i < TimedSections; ++i) {
      PassTiming& pass = out.passes[i];
      pass.name = SectionNames[i];
      pass.cpuMs = slot.cpuMs[i];
      pass.gpuMs = -1.0;
      if (withGpu) {
        GLuint64 ns = 0;
        glGetQueryObjectui64v(slot.queries[i], GL_QUERY_RESULT, &ns);
        pass.gpuMs = static_cast<double>(ns) * 1.0e-6;
      }
    }
  }

  // Publish every finished frame (oldest first) without waiting on the GPU.
  void collectFinished(RenderTimings& out)
  {
    while (pending > 0) {
      Slot& slot = oldest();
      GLuint ready = 0;
      glGetQueryObjectuiv(slot.queries[TimedSections - 1],
                          GL_QUERY_RESULT_AVAILABLE, &ready);
      if (!ready)
        break;
      publish(slot, true, out);
      --pending;
    }
  }

  void beginFrame(RenderTimings& out, bool synchronous)
  {
    if (!queriesCreated && frameCounter == 0)
      createQueries();
    if (gpuAvailable && !synchronous)
      collectFinished(out);
    // The ring is full of unread frames: drop the oldest to reuse its slot.
    if (pending == TimedSlots)
      --pending;
    current = &slots[next];
    current->frame = ++frameCounter;
    bytesAtStart = BufferObject::totalBytesUploaded();
    section = -1;
  }

  void beginSection(int index)
  {
    section = index;
    if (gpuAvailable)
      glBeginQuery(GL_TIME_ELAPSED, current->queries[index]);
    sectionStart = Clock::now();
  }

  void endSection()
  {
    if (section < 0)
      return;
    const Clock::time_point stop = Clock::now();
    current->cpuMs[section] =
      std::chrono::duration<double, std::milli>(stop - sectionStart).count();
    if (gpuAvailable)
      glEndQuery(GL_TIME_ELAPSED);
    section = -1;
  }

  void endFrame(RenderTimings& out, bool synchronous)
  {
    current->bytes = BufferObject::totalBytesUploaded() - bytesAtStart;
    if (!gpuAvailable) {
      publish(*current, false, out);
    } else if (synchronous) {
      // Anything still in flight is older than this frame; discard it.
      pending = 0;
      publish(*current, true, out);
    } else {
      ++pending;
    }
    next = (next + 1) % TimedSlots;
    current = nullptr;
  }
};

GLRenderer::GLRenderer()
  : m_valid(false), m_pixelRatio(1.0f), m_textRenderStrategy(nullptr),
    m_center(Vector3f::Zero()), m_radius(20.0)
#ifdef _3DCONNEXION
    ,
    m_drawIcon(false), m_iconData(nullptr), m_iconWidth(0u), m_iconHeight(0u),
    m_iconPosition(Eigen::Vector3f::Zero())
#endif
{
  m_overlayCamera.setIdentity();

  float aspectRatio = static_cast<float>(m_camera.width()) /
                      static_cast<float>(m_camera.height());
  float distance = m_camera.distance(m_center);
  float offset = distance + m_radius;
  m_perspectiveFrustum = {
    -aspectRatio, aspectRatio, -1.0f, 1.0f, 2.0f, offset
  };
  m_orthographicFrustum = {
    -5.0f * aspectRatio, 5.0f * aspectRatio, -5.0f, 5.0f, -offset, offset
  };
}

GLRenderer::~GLRenderer()
{
  delete m_textRenderStrategy;
}

void GLRenderer::setTimingEnabled(bool enable)
{
  m_timingEnabled = enable;
  if (enable && !m_timingState)
    m_timingState = std::make_unique<TimingState>();
}

void GLRenderer::initialize()
{
  GLenum result = glewInit();
  m_valid = (result == GLEW_OK || result == GLEW_ERROR_NO_GLX_DISPLAY);
  if (!m_valid) {
    m_error += "GLEW could not be initialized.\n";
    return;
  }

  if (!GLEW_VERSION_2_0) {
    m_error += "GL version 2.0 is not supported by your graphics driver.\n";
    m_valid = false;
    return;
  }

  m_solidPipeline.initialize();
}

void GLRenderer::resize(int width, int height)
{
  if (!m_valid)
    return;

  // m_volume.resize(width, height);
  // The viewport is in device pixels, while the cameras work in logical pixels
  // as they are used to project and unproject Qt mouse coordinates.
  glViewport(0, 0, static_cast<GLsizei>(width * m_pixelRatio),
             static_cast<GLsizei>(height * m_pixelRatio));
  m_camera.setViewport(width, height);
  m_overlayCamera.setViewport(width, height);
  m_solidPipeline.resize(width, height);
}

void GLRenderer::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
  m_solidPipeline.setPixelRatio(ratio);
}

void GLRenderer::render()
{
  if (!m_valid)
    return;

  TimingState* timing = m_timingEnabled ? m_timingState.get() : nullptr;
  if (timing) {
    timing->beginFrame(m_timings, m_timingSync);
    timing->beginSection(0);
  }

  Vector4ub c = m_scene.backgroundColor();
  glClearColor(c[0] / 255.0f, c[1] / 255.0f, c[2] / 255.0f, c[3] / 255.0f);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  applyProjection();

  GLRenderVisitor visitor(m_camera, m_textRenderStrategy);
  visitor.setPixelRatio(m_pixelRatio);
  // Setup for solid geometry
  // m_volume.begin()
  m_solidPipeline.begin();
  visitor.setRenderPass(SolidPass);
  glEnable(GL_DEPTH_TEST);
  glDisable(GL_BLEND);
  m_scene.rootNode().accept(visitor);
  if (timing) {
    timing->endSection();
    timing->beginSection(1);
  }
  // Before end(), so the offset the fog and depth-of-field are sized by
  // belongs to the camera this frame is drawn with rather than the last one.
  m_solidPipeline.adjustOffset(m_camera);
  m_solidPipeline.end(m_camera);
  if (timing) {
    timing->endSection();
    timing->beginSection(2);
  }

  // Setup for opaque geometry
  visitor.setRenderPass(OpaquePass);
  m_scene.rootNode().accept(visitor);
  if (timing) {
    timing->endSection();
    timing->beginSection(3);
  }

  // Setup for transparent geometry
  visitor.setRenderPass(TranslucentPass);
  glEnable(GL_BLEND);
  // Thanks to Giuseppe D'Angelo for a related comment:
  // https://bugreports.qt.io/browse/QTBUG-36739
  glBlendFuncSeparate(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA, GL_ONE, GL_ONE);
  m_scene.rootNode().accept(visitor);
  if (timing) {
    timing->endSection();
    timing->beginSection(4);
  }

  // Setup for 3d overlay rendering
  visitor.setRenderPass(Overlay3DPass);
  glClear(GL_DEPTH_BUFFER_BIT);
  m_scene.rootNode().accept(visitor);
  if (timing) {
    timing->endSection();
    timing->beginSection(5);
  }

  // Setup for 2d overlay rendering
  visitor.setRenderPass(Overlay2DPass);
  visitor.setCamera(m_overlayCamera);
  glDisable(GL_DEPTH_TEST);
  m_scene.rootNode().accept(visitor);
  if (timing) {
    timing->endSection();
    timing->endFrame(m_timings, m_timingSync);
  }

#ifdef _3DCONNEXION
  if (m_drawIcon && (m_iconData != nullptr)) {
    glPushMatrix();
    Eigen::Vector4f pivotPosition =
      m_camera.projection().matrix() * m_camera.modelView().matrix() *
      Eigen::Vector4f(m_iconPosition.x(), m_iconPosition.y(),
                      m_iconPosition.z(), 1.0);
    pivotPosition /= pivotPosition.w();
    glRasterPos3d(pivotPosition.x(), pivotPosition.y(), pivotPosition.z());
    glPixelZoom(1.0f, -1.0f);
    glBitmap(0.0f, 0.0f, 0.0f, 0.0f, -static_cast<float>(m_iconWidth >> 1),
             static_cast<float>(m_iconHeight >> 1), NULL);
    glDrawPixels(m_iconWidth, m_iconHeight, GL_BGRA_EXT, GL_UNSIGNED_BYTE,
                 m_iconData);
    glPopMatrix();
  }
#endif
}

void GLRenderer::resetCamera()
{
  resetGeometry();
  m_camera.setFocus(m_center);
  m_camera.setIdentity();
  m_camera.translate(-m_center);
  m_camera.preTranslate(-2.22f * m_radius * Vector3f::UnitZ());

  if (m_camera.projectionType() == Orthographic) {
    // The base orthographic frustum has half-height of 5.0
    // We want the scene radius to fit comfortably with some padding
    float baseHalfHeight = 5.0f;
    float optimalScale = m_radius / baseHalfHeight;
    m_camera.setOrthographicScale(optimalScale);
  }
}

void GLRenderer::resetGeometry()
{
  m_scene.setDirty(true);
  if (m_camera.focus()(0) != m_camera.focus()(0) ||
      m_camera.focus() == m_center)
    m_camera.setFocus(m_scene.center());
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
      void visit(CurveGeometry&) override { return; }
      void visit(CylinderGeometry&) override { return; }
      void visit(MeshGeometry&) override { return; }
      // void visit(Texture2D&) { return; }
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
  float aspectRatio = static_cast<float>(m_camera.width()) /
                      static_cast<float>(m_camera.height());
  if (m_camera.projectionType() == Perspective) {
    m_perspectiveFrustum[0] = m_perspectiveFrustum[2] * aspectRatio;
    m_perspectiveFrustum[1] = m_perspectiveFrustum[3] * aspectRatio;
    m_perspectiveFrustum[5] = distance + m_radius;
    m_camera.calculatePerspective(
      m_perspectiveFrustum[0], m_perspectiveFrustum[1], m_perspectiveFrustum[2],
      m_perspectiveFrustum[3], m_perspectiveFrustum[4],
      m_perspectiveFrustum[5]);
  } else {
    // Renders the orthographic projection of the molecule
    m_orthographicFrustum[0] = m_orthographicFrustum[2] * aspectRatio;
    m_orthographicFrustum[1] = m_orthographicFrustum[3] * aspectRatio;
    m_orthographicFrustum[5] = distance + m_radius;
    m_orthographicFrustum[4] = -m_orthographicFrustum[5];
    m_camera.calculateOrthographic(m_orthographicFrustum[0],  // L
                                   m_orthographicFrustum[1],  // R
                                   m_orthographicFrustum[2],  // B
                                   m_orthographicFrustum[3],  // T
                                   m_orthographicFrustum[4],  // N
                                   m_orthographicFrustum[5]); // F
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

  for (auto it : group->children()) {
    std::multimap<float, Identifier> loopHits;
    const Node* itNode = it.node;
    const auto* childGroup = dynamic_cast<const GroupNode*>(itNode);
    if (childGroup) {
      loopHits = hits(childGroup, rayOrigin, rayEnd, rayDirection);
      result.insert(loopHits.begin(), loopHits.end());
      continue;
    }
    const auto* childGeometry = itNode->cast<GeometryNode>();
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

  for (auto it : group->children()) {
    Array<Identifier> loopHits;
    const Node* itNode = it.node;
    const auto* childGroup = dynamic_cast<const GroupNode*>(itNode);
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

float GLRenderer::hit(const Vector3f& rayOrigin, const Vector3f& rayEnd,
                      const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> results =
    hits(&m_scene.rootNode(), rayOrigin, rayEnd, rayDirection);
  if (results.size())
    return results.begin()->first;
  return std::numeric_limits<float>::max();
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

  if (m_camera.projectionType() == Perspective) {
    f.planes[0] = (f.points[0] - f.points[1]).cross(f.points[2] - f.points[3]);
    f.planes[1] = (f.points[2] - f.points[3]).cross(f.points[4] - f.points[5]);
    f.planes[2] = (f.points[4] - f.points[5]).cross(f.points[6] - f.points[7]);
    f.planes[3] = (f.points[6] - f.points[7]).cross(f.points[0] - f.points[1]);
  } else {
    // Orthographic: planes are parallel, defined by edges and view direction

    // Left plane: normal points inward (to the right)
    Vector3f edge01 = (f.points[1] - f.points[0]).normalized();
    Vector3f edge02 = (f.points[2] - f.points[0]).normalized();
    f.planes[0] = edge01.cross(edge02).normalized();

    // Bottom plane: normal points inward (upward)
    Vector3f edge23 = (f.points[3] - f.points[2]).normalized();
    Vector3f edge24 = (f.points[4] - f.points[2]).normalized();
    f.planes[1] = edge23.cross(edge24).normalized();

    // Right plane: normal points inward (to the left)
    Vector3f edge45 = (f.points[5] - f.points[4]).normalized();
    Vector3f edge46 = (f.points[6] - f.points[4]).normalized();
    f.planes[2] = edge45.cross(edge46).normalized();

    // Top plane: normal points inward (downward)
    Vector3f edge67 = (f.points[7] - f.points[6]).normalized();
    Vector3f edge60 = (f.points[0] - f.points[6]).normalized();
    f.planes[3] = edge67.cross(edge60).normalized();
  }

  return hits(&m_scene.rootNode(), f);
}

} // namespace Avogadro::Rendering
