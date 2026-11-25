/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/solidpipeline.h>
#include <avogadro/rendering/spheregeometry.h>

#include <gtest/gtest.h>

#include <QtGui/QGuiApplication>
#include <QtGui/QOffscreenSurface>
#include <QtGui/QOpenGLContext>
#include <QtGui/QSurfaceFormat>

#include <memory>
#include <string>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GLRenderer;
using Avogadro::Rendering::SphereGeometry;
using namespace Avogadro::TestGL;

namespace {

// A GL context of the test's own, with no widget around it, so that the test
// decides when it is current and when it is destroyed.
class StandaloneGL
{
public:
  // Returns an empty string on success, else why there is no GL.
  std::string create()
  {
    if (ensureApp() == nullptr)
      return "A QApplication is required.";
    const QString platform = QGuiApplication::platformName();
    if (platform == "offscreen" || platform == "minimal")
      return "No OpenGL context on the " + platform.toStdString() +
             " platform.";
    m_context = std::make_unique<QOpenGLContext>();
    m_context->setFormat(QSurfaceFormat::defaultFormat());
    if (!m_context->create())
      return "Could not create an OpenGL context.";
    m_surface = std::make_unique<QOffscreenSurface>();
    m_surface->setFormat(m_context->format());
    m_surface->create();
    if (!m_surface->isValid())
      return "Could not create an offscreen surface.";
    return std::string();
  }

  bool makeCurrent() { return m_context->makeCurrent(m_surface.get()); }
  void doneCurrent() { m_context->doneCurrent(); }
  // Destroy the context (and surface) while no one is current.
  void destroyContext()
  {
    m_context.reset();
    m_surface.reset();
  }

private:
  std::unique_ptr<QOpenGLContext> m_context;
  std::unique_ptr<QOffscreenSurface> m_surface;
};

// A renderer that has drawn spheres and cylinders with ambient occlusion on,
// so the shader cache, the drawables' buffers and the SolidPipeline's
// framebuffers all exist. The context is current when this returns.
std::unique_ptr<GLRenderer> makeBusyRenderer(StandaloneGL& gl)
{
  auto renderer = std::make_unique<GLRenderer>();
  EXPECT_TRUE(gl.makeCurrent());
  renderer->initialize();
  EXPECT_TRUE(renderer->isValid()) << renderer->error();
  renderer->resize(64, 64);
  renderer->solidPipeline().setAoEnabled(true);

  auto* geometry = new GeometryNode;
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(-1, 0, 0), Vector3ub(255, 0, 0), 0.5f);
  geometry->addDrawable(spheres);
  auto* cylinders = new CylinderGeometry;
  cylinders->addCylinder(Vector3f(-1, 0, 0), Vector3f(1, 0, 0), 0.2f,
                         Vector3ub(0, 255, 0));
  geometry->addDrawable(cylinders);
  renderer->scene().rootNode().addChild(geometry);
  renderer->resetGeometry();
  renderer->resetCamera();

  renderer->render();
  EXPECT_TRUE(renderer->solidPipeline().hasActiveEffects());
  return renderer;
}

} // namespace

// Destroying a renderer that was never cleaned up, with no context current,
// must not crash or issue GL calls it cannot make.
TEST(RendererTeardownTest, destroyedWithoutCleanupAndNoCurrentContext)
{
  StandaloneGL gl;
  const std::string reason = gl.create();
  if (!reason.empty())
    GTEST_SKIP() << reason;

  auto renderer = makeBusyRenderer(gl);
  gl.doneCurrent();
  EXPECT_EQ(QOpenGLContext::currentContext(), nullptr);
  renderer.reset();
  SUCCEED();
}

// The same after the context itself has been destroyed.
TEST(RendererTeardownTest, destroyedAfterTheContextIsGone)
{
  StandaloneGL gl;
  const std::string reason = gl.create();
  if (!reason.empty())
    GTEST_SKIP() << reason;

  auto renderer = makeBusyRenderer(gl);
  gl.doneCurrent();
  gl.destroyContext();
  EXPECT_EQ(QOpenGLContext::currentContext(), nullptr);
  renderer.reset();
  SUCCEED();
}

// The supported order: cleanup() with the context current, then destroy.
TEST(RendererTeardownTest, cleanupThenDestroyWithNoCurrentContext)
{
  StandaloneGL gl;
  const std::string reason = gl.create();
  if (!reason.empty())
    GTEST_SKIP() << reason;

  auto renderer = makeBusyRenderer(gl);
  renderer->cleanup();
  renderer->scene().clear();
  gl.doneCurrent();
  renderer.reset();
  SUCCEED();
}
