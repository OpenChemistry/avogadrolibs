/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/solidpipeline.h>
#include <avogadro/rendering/spheregeometry.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <gtest/gtest.h>

#include <array>
#include <memory>

using namespace Avogadro;
using namespace Avogadro::Rendering;

class SolidPipelineGLTest : public testing::Test
{
protected:
  void SetUp() override
  {
    // EGL returns an untyped function pointer; use the extension signature.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto getDisplay = reinterpret_cast<PFNEGLGETPLATFORMDISPLAYEXTPROC>(
      eglGetProcAddress("eglGetPlatformDisplayEXT"));
    if (!getDisplay)
      GTEST_SKIP() << "Surfaceless EGL is unavailable";
    display =
      getDisplay(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, nullptr);
    EGLint major = 0, minor = 0;
    if (!eglInitialize(display, &major, &minor))
      GTEST_SKIP() << "No surfaceless EGL driver";
    ASSERT_TRUE(eglBindAPI(EGL_OPENGL_API));
    const std::array attributes = { EGL_SURFACE_TYPE,
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
    EGLint count = 0;
    ASSERT_TRUE(
      eglChooseConfig(display, attributes.data(), &config, 1, &count));
    if (count == 0)
      GTEST_SKIP() << "No OpenGL pbuffer configuration";
    const std::array surfaceAttributes = { EGL_WIDTH, 64, EGL_HEIGHT, 64,
                                           EGL_NONE };
    surface =
      eglCreatePbufferSurface(display, config, surfaceAttributes.data());
    context = createContext();
    if (context == EGL_NO_CONTEXT)
      GTEST_SKIP() << "OpenGL 4 is unavailable";
    ASSERT_TRUE(eglMakeCurrent(display, surface, surface, context));
  }

  EGLContext createContext()
  {
    const std::array contextAttributes = { EGL_CONTEXT_MAJOR_VERSION, 4,
                                           EGL_CONTEXT_MINOR_VERSION, 0,
                                           EGL_NONE };
    return eglCreateContext(display, config, EGL_NO_CONTEXT,
                            contextAttributes.data());
  }

  // Count the framebuffer and texture names that currently exist, as a proxy
  // for the pipeline's resources (it exposes none of its names).
  static int countObjects()
  {
    int count = 0;
    for (GLuint name = 1; name <= 256; ++name) {
      if (glIsFramebuffer(name) == GL_TRUE)
        ++count;
      if (glIsTexture(name) == GL_TRUE)
        ++count;
    }
    return count;
  }

  static void drainErrors()
  {
    for (int i = 0; i < 32 && glGetError() != GL_NO_ERROR; ++i) {}
  }

  // Release the current context and destroy it.
  void destroyContext()
  {
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (context != EGL_NO_CONTEXT)
      eglDestroyContext(display, context);
    context = EGL_NO_CONTEXT;
  }

  void TearDown() override
  {
    if (display == EGL_NO_DISPLAY)
      return;
    destroyContext();
    if (surface != EGL_NO_SURFACE)
      eglDestroySurface(display, surface);
    eglTerminate(display);
  }

protected:
  EGLConfig config = nullptr;
  EGLDisplay display = EGL_NO_DISPLAY;
  EGLSurface surface = EGL_NO_SURFACE;
  EGLContext context = EGL_NO_CONTEXT;
};

TEST_F(SolidPipelineGLTest, SolidPipelineRendersWithAndWithoutAmbientOcclusion)
{
  GLRenderer renderer;
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  // GLEW can leave an error when querying a core profile's extension string.
  drainErrors();
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
    std::array<unsigned char, 4> pixel{};
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel.data());
    EXPECT_EQ(glGetError(), GL_NO_ERROR);
    EXPECT_GT(pixel[0], pixel[1]);
    EXPECT_GT(pixel[0], pixel[2]);
  }
}

TEST_F(SolidPipelineGLTest, ReinitializeAfterCleanupOnSameContext)
{
  SolidPipeline pipeline;
  drainErrors();
  const int baseline = countObjects();
  pipeline.initialize();
  EXPECT_GT(countObjects(), baseline);
  pipeline.releaseResources();
  EXPECT_EQ(countObjects(), baseline);
  pipeline.initialize();
  EXPECT_GT(countObjects(), baseline);
  EXPECT_EQ(glGetError(), GL_NO_ERROR);
  pipeline.releaseResources();
  EXPECT_EQ(countObjects(), baseline);
}

TEST_F(SolidPipelineGLTest, ReleaseTwiceThenDestroyAfterContext)
{
  auto pipeline = std::make_unique<SolidPipeline>();
  pipeline->initialize();
  pipeline->releaseResources();
  pipeline->releaseResources();
  // With the context gone, a pipeline that holds no names must not touch GL.
  destroyContext();
  pipeline.reset();
  SUCCEED();
}

TEST_F(SolidPipelineGLTest, RendererCleanupIsIdempotent)
{
  auto renderer = std::make_unique<GLRenderer>();
  renderer->initialize();
  ASSERT_TRUE(renderer->isValid()) << renderer->error();
  renderer->cleanup();
  renderer->cleanup();
  destroyContext();
  renderer.reset();
  SUCCEED();
}

TEST_F(SolidPipelineGLTest, ReinitializeWithoutCleanupDoesNotLeak)
{
  SolidPipeline pipeline;
  drainErrors();
  const int baseline = countObjects();
  pipeline.initialize();
  const int first = countObjects();
  pipeline.initialize();
  EXPECT_EQ(countObjects(), first);
  EXPECT_EQ(glGetError(), GL_NO_ERROR);
  pipeline.releaseResources();
  EXPECT_EQ(countObjects(), baseline);
}

TEST_F(SolidPipelineGLTest, ContextRecreation)
{
  GLRenderer renderer;
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  renderer.cleanup();
  destroyContext();
  context = createContext();
  ASSERT_NE(context, EGL_NO_CONTEXT);
  ASSERT_TRUE(eglMakeCurrent(display, surface, surface, context));
  drainErrors();
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  drainErrors();
  renderer.resize(64, 64);
  renderer.resetCamera();
  renderer.solidPipeline().setAoEnabled(true);
  renderer.render();
  EXPECT_EQ(glGetError(), GL_NO_ERROR);
  renderer.cleanup();
}
