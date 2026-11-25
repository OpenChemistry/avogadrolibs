/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "solidpipeline.h"

#include "avogadrogl.h"
#include "camera.h"
#include "rendercontext_p.h"
#include "shaderprogram.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <string>

#ifdef __EMSCRIPTEN__
#include <emscripten/html5.h>
#endif

namespace Avogadro::Rendering {

// Texture units shared by the pipeline's stages. Kept together so that adding
// a sampler cannot silently collide with one already in use.
namespace {
constexpr int TextureUnitRGB = 1;
constexpr int TextureUnitDepth = 2;
constexpr int TextureUnitAo = 3;

// Delete a GL object and zero its name; zero names are skipped.
void deleteTexture(GLuint& name)
{
  if (name != 0) {
    glDeleteTextures(1, &name);
    name = 0;
  }
}

void deleteFramebuffer(GLuint& name)
{
  if (name != 0) {
    glDeleteFramebuffers(1, &name);
    name = 0;
  }
}

void deleteVertexArray(GLuint& name)
{
  if (name != 0) {
    glDeleteVertexArrays(1, &name);
    name = 0;
  }
}
} // namespace

class SolidPipeline::Private
{
public:
  Private() {}

  // Point a sampler uniform at a texture. The program is taken rather than
  // read back from the GL state: asking the driver which program is bound
  // stalls, and the program's own uniform lookup is cached where
  // glGetUniformLocation is not.
  static void bindSampler(ShaderProgram& prog, const std::string& name,
                          GLuint texture, int unit)
  {
    glActiveTexture(GL_TEXTURE0 + unit);
    glBindTexture(GL_TEXTURE_2D, texture);
    prog.setUniformValue(name, unit);
  }

  void attachStage(ShaderProgram& prog, const std::string& nameRGB,
                   GLuint texRGB, const std::string& nameDepth, GLuint texDepth,
                   int w, int h)
  {
    prog.bind();
    bindSampler(prog, nameRGB, texRGB, TextureUnitRGB);
    bindSampler(prog, nameDepth, texDepth, TextureUnitDepth);
    prog.setUniformValue("width", static_cast<float>(w));
    prog.setUniformValue("height", static_cast<float>(h));
  }

  // Settings live here rather than in the header's members so that adding one
  // does not change the size of the installed class.
  bool edgeSupersampling = true;
  bool antiAliasing = false;
  // The clear colour at begin(): the background that FXAA fills the composite
  // with and blends silhouettes into.
  GLfloat clearColor[4] = { 0.0f, 0.0f, 0.0f, 0.0f };

  // The composited image FXAA reads, created on first use because most
  // sessions never enable it. fxaaState: 0 = not tried, 1 = ready, -1 = the
  // framebuffer was incomplete and FXAA is skipped.
  GLuint compositeFBO = 0;
  GLuint compositeTexture = 0;
  int compositeWidth = 0;
  int compositeHeight = 0;
  int fxaaState = 0;

  // Build the composite target if it is missing or the wrong size. Needs the
  // context current. Returns false if FXAA cannot run.
  bool prepareFxaa(int w, int h)
  {
    if (fxaaState < 0)
      return false;
    if (compositeFBO != 0 && compositeWidth == w && compositeHeight == h)
      return true;

    GLint previousFBO = 0;
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &previousFBO);
    GLint previousTexture = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &previousTexture);
    if (compositeFBO == 0) {
      glGenFramebuffers(1, &compositeFBO);
      glGenTextures(1, &compositeTexture);
      glBindTexture(GL_TEXTURE_2D, compositeTexture);
      // Linear: the filter's half-pixel taps average two pixels each.
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
      glBindFramebuffer(GL_FRAMEBUFFER, compositeFBO);
      glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                             GL_TEXTURE_2D, compositeTexture, 0);
    } else {
      glBindTexture(GL_TEXTURE_2D, compositeTexture);
      glBindFramebuffer(GL_FRAMEBUFFER, compositeFBO);
    }
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                 nullptr);
    const bool complete =
      glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
    glBindFramebuffer(GL_FRAMEBUFFER, static_cast<GLuint>(previousFBO));
    glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(previousTexture));
    if (!complete) {
      fxaaState = -1;
      return false;
    }
    compositeWidth = w;
    compositeHeight = h;
    fxaaState = 1;
    return true;
  }

  bool initialized = false;
  bool framebufferReady = false;
  bool aoSupported = true;
  bool aoReady = false;
  GLuint defaultFBO = 0;
  GLint defaultViewport[4] = { 0, 0, 0, 0 };
  GLuint renderFBO = 0;
  GLuint renderTexture = 0;
  GLuint depthTexture = 0;
  GLuint aoFBO = 0;
  GLuint aoTexture = 0;
  GLuint screenVAO = 0;
};

void initializeFramebuffer(GLuint* outFBO, GLuint* texRGB, GLuint* texDepth)
{
  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  glGenTextures(1, texRGB);
  glBindTexture(GL_TEXTURE_2D, *texRGB);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         *texRGB, 0);

  glGenTextures(1, texDepth);
  glBindTexture(GL_TEXTURE_2D, *texDepth);
#ifdef __EMSCRIPTEN__
  const GLint depthFilter = GL_NEAREST;
#else
  const GLint depthFilter = GL_LINEAR;
#endif
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, depthFilter);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, depthFilter);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_DEPTH_ATTACHMENT, GL_TEXTURE_2D,
                         *texDepth, 0);
}

// The ambient occlusion term is rendered on its own so the compositing stage
// can filter it, with the distance to the surface in the second channel so
// that the filter's surface test costs no extra fetch. It needs a float
// format: the term brightens as well as darkens, and goes above 1.0.
void initializeAoFramebuffer(GLuint* outFBO, GLuint* texAo)
{
  glGenFramebuffers(1, outFBO);
  glBindFramebuffer(GL_FRAMEBUFFER, *outFBO);

  glGenTextures(1, texAo);
  glBindTexture(GL_TEXTURE_2D, *texAo);
  // The blur reads exact texel centres, so no filtering is wanted here.
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D,
                         *texAo, 0);
}

SolidPipeline::SolidPipeline()
  : m_pixelRatio(1.0f), m_aoEnabled(false), m_dofStrength(1.0f),
    m_dofPosition(1.0), m_dofEnabled(false), m_fogPosition(1.0),
    m_backgroundColor(0, 0, 0, 0), m_fogEnabled(true), m_aoStrength(1.0f),
    m_fogStrength(1.0f), m_edEnabled(false), m_edStrength(1.0f), m_width(0),
    m_height(0), d(new Private)
{
}

SolidPipeline::~SolidPipeline()
{
  releaseResources();
  delete d;
}

void SolidPipeline::releaseResources()
{
  deleteFramebuffer(d->renderFBO);
  deleteTexture(d->renderTexture);
  deleteTexture(d->depthTexture);
  deleteFramebuffer(d->aoFBO);
  deleteTexture(d->aoTexture);
  deleteVertexArray(d->screenVAO);
  deleteFramebuffer(d->compositeFBO);
  deleteTexture(d->compositeTexture);
  d->compositeWidth = 0;
  d->compositeHeight = 0;
  d->fxaaState = 0;
  d->initialized = false;
  d->framebufferReady = false;
  d->aoReady = false;
  // A failure on a previous context says nothing about the next one.
  d->aoSupported = true;
}

void SolidPipeline::initialize()
{
  // Also needed after a failed initialize(): the framebuffers and VAO exist
  // even when a shader did not compile. Zero names are skipped.
  releaseResources();

  GLint previousFBO = 0;
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, &previousFBO);
#ifdef __EMSCRIPTEN__
  // Floating-point color attachments are optional even in WebGL 2.
  d->aoSupported = emscripten_webgl_enable_extension(
    emscripten_webgl_get_current_context(), "EXT_color_buffer_float");
#endif
  initializeFramebuffer(&d->renderFBO, &d->renderTexture, &d->depthTexture);
  initializeAoFramebuffer(&d->aoFBO, &d->aoTexture);
  // Each helper leaves its own framebuffer bound; settle on the one the
  // pipeline renders into.
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);

  // Empty VAO for the procedural fullscreen triangle (required for Core
  // Profile; vertex positions are generated from gl_VertexID in solid_vs.glsl).
  glGenVertexArrays(1, &d->screenVAO);

  // The shader programs belong to the render context and are built on first
  // use in begin() and end(), where it is current.
  d->initialized = true;
  glBindFramebuffer(GL_FRAMEBUFFER, static_cast<GLuint>(previousFBO));
}

bool SolidPipeline::begin()
{
  if (!hasActiveEffects() || !d->initialized || !d->framebufferReady)
    return false;
  // Without the compositing program the offscreen image could never be drawn,
  // so leave the solid geometry to render directly.
  FallbackRenderContext fallbackContext;
  if (RenderContext::currentProgram(ShaderId::SolidFirst) == nullptr)
    return false;
  glGetIntegerv(GL_FRAMEBUFFER_BINDING,
                reinterpret_cast<GLint*>(&d->defaultFBO));
  glGetIntegerv(GL_VIEWPORT, d->defaultViewport);
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);
  GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
  glDrawBuffers(1, drawBuffersList);

  // The offscreen buffers are sized independently of the default framebuffer,
  // so the viewport must be set to match them rather than inherited. They can
  // disagree whenever the device pixel ratio changes without a resize, such as
  // when the window is dragged to a monitor with a different scale factor.
  glViewport(0, 0, static_cast<GLsizei>(m_width),
             static_cast<GLsizei>(m_height));

  GLfloat tmp[5];
  glGetFloatv(GL_COLOR_CLEAR_VALUE, tmp);
  glGetFloatv(GL_DEPTH_CLEAR_VALUE, tmp + 4);
  glClearColor(0.0, 0.0, 0.0, 0.0);
  glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
  glClearColor(tmp[0], tmp[1], tmp[2], tmp[3]);
  std::copy(tmp, tmp + 4, d->clearColor);
#ifdef __EMSCRIPTEN__
  glClearDepthf(tmp[4]);
#else
  glClearDepth(tmp[4]);
#endif
  return true;
}

void SolidPipeline::end(const Camera& camera)
{
  if (!d->initialized)
    return;

  FallbackRenderContext fallbackContext;
  ShaderProgram* firstStage =
    RenderContext::currentProgram(ShaderId::SolidFirst);
  if (firstStage == nullptr || !RenderContext::useCamera(camera))
    return;

  // Bind VAO for procedural fullscreen triangle (required for Core Profile)
  glBindVertexArray(d->screenVAO);

  // Render the ambient occlusion term into its own buffer first, so the
  // compositing stage can blur away the kernel's sampling pattern. Skipped
  // entirely when ambient occlusion is off, since nothing would read it.
  ShaderProgram* aoStage = nullptr;
  if (m_aoEnabled && d->aoReady)
    aoStage = RenderContext::currentProgram(ShaderId::SolidAo);
  const bool useAo = aoStage != nullptr;
  if (useAo) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->aoFBO);
    GLenum aoBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, aoBuffersList);
    glViewport(0, 0, static_cast<GLsizei>(m_width),
               static_cast<GLsizei>(m_height));
    // This target has no depth attachment, and the pass covers every pixel.
    glDisable(GL_DEPTH_TEST);

    aoStage->bind();
    d->bindSampler(*aoStage, "inDepthTex", d->depthTexture, TextureUnitDepth);
    aoStage->setUniformValue("width", static_cast<float>(m_width));
    aoStage->setUniformValue("height", static_cast<float>(m_height));
    aoStage->setUniformValue("inAoStrength", m_aoStrength);
    glDrawArrays(GL_TRIANGLES, 0, 3);

    // The passes that follow this one still depend on depth testing.
    glEnable(GL_DEPTH_TEST);
  }

  // FXAA needs the composited image as a texture, so with it on the compositing
  // stage draws into one instead of the framebuffer, and a last pass filters
  // it into the framebuffer. The composite starts as the background, since
  // the compositing stage leaves background pixels alone.
  ShaderProgram* fxaaStage = nullptr;
  if (d->antiAliasing)
    fxaaStage = RenderContext::currentProgram(ShaderId::SolidFxaa);
  const bool useFxaa =
    fxaaStage != nullptr && d->prepareFxaa(m_width, m_height);

  // Draw to screen
  auto bindScreen = [this]() {
    if (glIsFramebuffer(d->defaultFBO)) {
      glBindFramebuffer(GL_FRAMEBUFFER, d->defaultFBO);
      GLenum drawBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
      glDrawBuffers(1, drawBuffersList);
    } else {
      glBindFramebuffer(GL_FRAMEBUFFER, 0);
#ifdef __EMSCRIPTEN__
      const GLenum back = GL_BACK;
      glDrawBuffers(1, &back);
#else
      glDrawBuffer(GL_BACK);
#endif
    }
    glViewport(d->defaultViewport[0], d->defaultViewport[1],
               d->defaultViewport[2], d->defaultViewport[3]);
  };
  if (useFxaa) {
    glBindFramebuffer(GL_FRAMEBUFFER, d->compositeFBO);
    GLenum compositeBuffersList[1] = { GL_COLOR_ATTACHMENT0 };
    glDrawBuffers(1, compositeBuffersList);
    glViewport(0, 0, static_cast<GLsizei>(m_width),
               static_cast<GLsizei>(m_height));
    // The clear colour is already the background; set it anyway rather than
    // depend on what ran in between.
    glClearColor(d->clearColor[0], d->clearColor[1], d->clearColor[2],
                 d->clearColor[3]);
    glClear(GL_COLOR_BUFFER_BIT);
  } else {
    bindScreen();
  }
  d->attachStage(*firstStage, "inRGBTex", d->renderTexture, "inDepthTex",
                 d->depthTexture, m_width, m_height);
  firstStage->setUniformValue("inAoEnabled", useAo ? 1.0f : 0.0f);
  firstStage->setUniformValue("inDofEnabled", m_dofEnabled ? 1.0f : 0.0f);
  firstStage->setUniformValue("inDofStrength",
                              m_dofEnabled ? (m_dofStrength * 100.0f) : 0.0f);
  firstStage->setUniformValue("inDofPosition", ((m_dofPosition) / 10.0f));

  // The AO term; the blur sizes its surface test with the camera block's
  // projection.
  d->bindSampler(*firstStage, "inAoTex", d->aoTexture, TextureUnitAo);
  firstStage->setUniformValue("inEdStrength",
                              m_edEnabled ? m_edStrength : 0.0f);
  firstStage->setUniformValue("inEdgeSupersample",
                              d->edgeSupersampling ? 1.0f : 0.0f);
  firstStage->setUniformValue("inFogEnabled", m_fogEnabled ? 1.0f : 0.0f);
  firstStage->setUniformValue("inFogStrength",
                              m_fogEnabled ? m_fogStrength : 0.0f);
  firstStage->setUniformValue("inFogPosition", m_fogPosition);
  firstStage->setUniformValue("fogR", (m_backgroundColor[0]) / 255.0f);
  firstStage->setUniformValue("fogG", (m_backgroundColor[1]) / 255.0f);
  firstStage->setUniformValue("fogB", (m_backgroundColor[2]) / 255.0f);
  glDrawArrays(GL_TRIANGLES, 0, 3);

  if (useFxaa) {
    bindScreen();
    // Edge pixels of the background are written too, at the background's own
    // depth of 1.0, which a strict depth test would reject.
    GLint depthFunc = GL_LESS;
    glGetIntegerv(GL_DEPTH_FUNC, &depthFunc);
    glDepthFunc(GL_LEQUAL);
    ShaderProgram& fxaa = *fxaaStage;
    fxaa.bind();
    d->bindSampler(fxaa, "inRGBTex", d->compositeTexture, TextureUnitRGB);
    d->bindSampler(fxaa, "inDepthTex", d->depthTexture, TextureUnitDepth);
    fxaa.setUniformValue("width", static_cast<float>(m_width));
    fxaa.setUniformValue("height", static_cast<float>(m_height));
    // Coverage only counts as contrast when the background can be seen
    // through.
    fxaa.setUniformValue("inAlphaWeight",
                         d->clearColor[3] < 1.0f ? 1.0f : 0.0f);
    glDrawArrays(GL_TRIANGLES, 0, 3);
    glDepthFunc(static_cast<GLenum>(depthFunc));
  }
  glBindVertexArray(0);
}

void SolidPipeline::adjustOffset(const Camera& cam)
{
  if (!d->initialized || (!m_fogEnabled && !m_dofEnabled))
    return;

  // The numbers used in calculations are random.
  // They help define an offset with the projection-matrix
  // to make the fog dynamic as the molecule moves away
  // from the camera or come closer.
  Eigen::Matrix4f projectView = cam.projection().matrix();

  float project = ((((5000 + projectView(2, 3) * 1000) / 6) + 55) * 100);

  float offSet = 0.000102337 * pow(project, 2) - 3.84689 * project + 36182.2;
  if (project >= 21018.106 && project < 21595.588) {
    offSet = 2.63129 * project - 54768.4;
  } else if (project >= 21595.588) {
    offSet = 9.952 * project - 212865;
  }
  // Uniforms land on whichever program is bound, so bind the one this is
  // meant for rather than depending on what the last pass left behind.
  ShaderProgram* firstStage =
    RenderContext::currentProgram(ShaderId::SolidFirst);
  if (firstStage == nullptr)
    return;
  firstStage->bind();
  firstStage->setUniformValue("uoffset", offSet);
}

void SolidPipeline::resize(int width, int height)
{
  resizeDevice(static_cast<int>(width * m_pixelRatio),
               static_cast<int>(height * m_pixelRatio));
}

void SolidPipeline::resizeDevice(int deviceWidth, int deviceHeight)
{
  m_width = deviceWidth;
  m_height = deviceHeight;

  d->framebufferReady = false;
  d->aoReady = false;
  if (!d->initialized || m_width <= 0 || m_height <= 0)
    return;
  GLint previousFBO = 0;
  glGetIntegerv(GL_FRAMEBUFFER_BINDING, &previousFBO);

  glBindTexture(GL_TEXTURE_2D, d->renderTexture);
#ifdef __EMSCRIPTEN__
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, m_width, m_height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, nullptr);
#else
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, m_width, m_height, 0, GL_RGBA,
               GL_UNSIGNED_BYTE, nullptr);
#endif

  glBindTexture(GL_TEXTURE_2D, d->depthTexture);
#ifdef __EMSCRIPTEN__
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT24, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_INT, nullptr);
#else
  glTexImage2D(GL_TEXTURE_2D, 0, GL_DEPTH_COMPONENT, m_width, m_height, 0,
               GL_DEPTH_COMPONENT, GL_UNSIGNED_BYTE, nullptr);
#endif

  // Two channels: the occlusion term and the distance to the surface.
  //
  // Half floats hold that distance to one part in 2048. Both the distance and
  // the blur's surface tolerance scale with the view, so what matters is their
  // ratio, which holds regardless of molecule size or projection: simulated
  // against a full-precision blur, the quantization is 0.8% of the tolerance
  // at 800 px tall and 2.5% at 2400 px, moving the blurred term by 2e-4 RMS.
  // That is two orders of magnitude below the dither this blur exists to
  // remove, so the extra channel is worth far more than the precision costs.
  //
  // The format tops out at 65504, so a camera further than that many scene
  // units from the geometry would lose the surface test. Nothing chemical
  // comes near it.
  glBindTexture(GL_TEXTURE_2D, d->aoTexture);
  if (d->aoSupported) {
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RG16F, m_width, m_height, 0, GL_RG,
                 GL_FLOAT, nullptr);
    glBindFramebuffer(GL_FRAMEBUFFER, d->aoFBO);
    d->aoReady =
      glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
  } else {
    // Keep the composite shader's unused sampler complete without requiring
    // a floating-point render target.
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                 nullptr);
  }
  glBindFramebuffer(GL_FRAMEBUFFER, d->renderFBO);
  d->framebufferReady =
    glCheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
  glBindFramebuffer(GL_FRAMEBUFFER, static_cast<GLuint>(previousFBO));
}

bool SolidPipeline::antiAliasingEnabled() const
{
  return d->antiAliasing;
}

void SolidPipeline::setAntiAliasingEnabled(bool enabled)
{
  d->antiAliasing = enabled;
}

bool SolidPipeline::edgeSupersampling() const
{
  return d->edgeSupersampling;
}

void SolidPipeline::setEdgeSupersampling(bool enabled)
{
  d->edgeSupersampling = enabled;
}

void SolidPipeline::setPixelRatio(float ratio)
{
  m_pixelRatio = ratio;
}

} // End namespace Avogadro::Rendering
