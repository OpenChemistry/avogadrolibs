/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/shader.h>
#include <avogadro/rendering/shaderprogram.h>

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <gtest/gtest.h>

#include <array>

using namespace Avogadro;
using namespace Avogadro::Rendering;

class ShaderLinkGLTest : public testing::Test
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
    EGLConfig config = nullptr;
    EGLint count = 0;
    ASSERT_TRUE(
      eglChooseConfig(display, attributes.data(), &config, 1, &count));
    if (count == 0)
      GTEST_SKIP() << "No OpenGL pbuffer configuration";
    const std::array surfaceAttributes = { EGL_WIDTH, 64, EGL_HEIGHT, 64,
                                           EGL_NONE };
    surface =
      eglCreatePbufferSurface(display, config, surfaceAttributes.data());
    const std::array contextAttributes = { EGL_CONTEXT_MAJOR_VERSION, 4,
                                           EGL_CONTEXT_MINOR_VERSION, 0,
                                           EGL_NONE };
    context = eglCreateContext(display, config, EGL_NO_CONTEXT,
                               contextAttributes.data());
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

private:
  EGLDisplay display = EGL_NO_DISPLAY;
  EGLSurface surface = EGL_NO_SURFACE;
  EGLContext context = EGL_NO_CONTEXT;
};

TEST_F(ShaderLinkGLTest, ReportsProgramLinkLog)
{
  ASSERT_TRUE(glewInit() == GLEW_OK || GLEW_VERSION_2_0);
  Shader vertex;
  vertex.setType(Shader::Vertex);
  vertex.setSource("#version 330\nout vec3 value;\n"
                   "void main() { value = vec3(1); gl_Position = vec4(0); }");
  Shader fragment;
  fragment.setType(Shader::Fragment);
  fragment.setSource("#version 330\nin vec4 value;\nout vec4 color;\n"
                     "void main() { color = value; }");
  ASSERT_TRUE(vertex.compile()) << vertex.error();
  ASSERT_TRUE(fragment.compile()) << fragment.error();
  ShaderProgram program;
  program.attachShader(vertex);
  program.attachShader(fragment);
  EXPECT_FALSE(program.link());
  EXPECT_FALSE(program.error().empty());
}
