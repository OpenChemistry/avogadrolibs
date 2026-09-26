/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/spheregeometry.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <gtest/gtest.h>

using namespace Avogadro;
using namespace Avogadro::Rendering;

class GLRendererTest : public testing::Test
{
protected:
  void SetUp() override
  {
    const auto getDisplay = reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(
      eglGetProcAddress("eglGetPlatformDisplayEXT"));
    if (!getDisplay)
      GTEST_SKIP() << "Surfaceless EGL is unavailable";
    display =
      getDisplay(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, nullptr);
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor))
      GTEST_SKIP() << "No surfaceless EGL driver";
    ASSERT_TRUE(eglBindAPI(EGL_OPENGL_API));
    const EGLint attributes[] = { EGL_SURFACE_TYPE,
                                  EGL_PBUFFER_BIT,
                                  EGL_RENDERABLE_TYPE,
                                  EGL_OPENGL_BIT,
                                  EGL_RED_SIZE,
                                  8,
                                  EGL_GREEN_SIZE,
                                  8,
                                  EGL_BLUE_SIZE,
                                  8,
                                  EGL_DEPTH_SIZE,
                                  24,
                                  EGL_NONE };
    EGLConfig config;
    EGLint count;
    ASSERT_TRUE(eglChooseConfig(display, attributes, &config, 1, &count));
    if (count == 0)
      GTEST_SKIP() << "No OpenGL pbuffer configuration";
    const EGLint surfaceAttributes[] = { EGL_WIDTH, 64, EGL_HEIGHT, 64,
                                         EGL_NONE };
    surface = eglCreatePbufferSurface(display, config, surfaceAttributes);
    const EGLint contextAttributes[] = { EGL_CONTEXT_MAJOR_VERSION, 4,
                                         EGL_CONTEXT_MINOR_VERSION, 0,
                                         EGL_NONE };
    context =
      eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
    if (context == EGL_NO_CONTEXT)
      GTEST_SKIP() << "OpenGL 4 is unavailable";
    ASSERT_TRUE(eglMakeCurrent(display, surface, surface, context));
  }

  void TearDown() override
  {
    if (display == EGL_NO_DISPLAY)
      return;
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (context != EGL_NO_CONTEXT)
      eglDestroyContext(display, context);
    if (surface != EGL_NO_SURFACE)
      eglDestroySurface(display, surface);
    eglTerminate(display);
  }

  EGLDisplay display = EGL_NO_DISPLAY;
  EGLSurface surface = EGL_NO_SURFACE;
  EGLContext context = EGL_NO_CONTEXT;
};

TEST_F(GLRendererTest, SolidPipelineRendersWithAndWithoutAmbientOcclusion)
{
  GLRenderer renderer;
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  // GLEW can leave an error when querying a core profile's extension string.
  while (glGetError() != GL_NO_ERROR) {}
  renderer.resize(64, 64);
  auto* geometry = new GeometryNode;
  auto* sphere = new SphereGeometry;
  sphere->addSphere(Vector3f::Zero(), Vector3ub(255, 0, 0), 1.0f);
  geometry->addDrawable(sphere);
  renderer.scene().rootNode().addChild(geometry);
  renderer.resetCamera();
  for (bool ao : { false, true }) {
    SCOPED_TRACE(ao);
    renderer.solidPipeline().setAoEnabled(ao);
    renderer.render();
    unsigned char pixel[4] = {};
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
    EXPECT_EQ(glGetError(), GL_NO_ERROR);
    EXPECT_GT(pixel[0], pixel[1]);
    EXPECT_GT(pixel[0], pixel[2]);
  }
}
