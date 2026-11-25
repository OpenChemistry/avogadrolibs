/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/qtopengl/qttextrenderstrategy.h>
#include <avogadro/qtopengl/renderoptions.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/bufferobject.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/cylindergeometry.h>
#include <avogadro/rendering/dashedlinegeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/linestripgeometry.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/shader.h>
#include <avogadro/rendering/shaderprogram.h>
#include <avogadro/rendering/solidpipeline.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textrenderstrategy.h>
#include <avogadro/rendering/texture2d.h>
#include <avogadro/rendering/vertexarrayobject.h>
#include <avogadro/rendering/widelinegeometry.h>

#include <QtGui/QImage>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLExtraFunctions>
#include <QtGui/QOpenGLFunctions>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <memory>
#include <string>
#include <vector>

using Avogadro::Vector2i;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::QtOpenGL::RenderOptions;
using Avogadro::Rendering::ArrowGeometry;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::BufferObject;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::CylinderGeometry;
using Avogadro::Rendering::DashedLineGeometry;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GLRenderer;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::LineStripGeometry;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::Orthographic;
using Avogadro::Rendering::Perspective;
using Avogadro::Rendering::Shader;
using Avogadro::Rendering::ShaderProgram;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::Texture2D;
using Avogadro::Rendering::TranslucentPass;
using Avogadro::Rendering::VertexArrayObject;
using Avogadro::Rendering::WideLineGeometry;
using namespace Avogadro::TestGL;

namespace {

const Vector4ub Background(40, 80, 120, 255);

// The error GL has recorded since the last drain, with the widget's context
// current. Goes through QOpenGLFunctions: the test binary does not link
// opengl32 on Windows.
GLenum currentGLError()
{
  return QOpenGLContext::currentContext()->functions()->glGetError();
}

// A drawable that does no GL and records which pass it is rendered in.
class CountingDrawable : public Avogadro::Rendering::Drawable
{
public:
  CountingDrawable(int id, Avogadro::Rendering::RenderPass pass,
                   std::vector<int>& log)
    : m_id(id), m_log(log)
  {
    setRenderPass(pass);
  }
  void render(const Camera&) override { m_log.push_back(m_id); }

private:
  int m_id;
  std::vector<int>& m_log;
};

// Rasterizes through the Qt strategy and counts the calls.
class RenderCountingStrategy : public Avogadro::Rendering::TextRenderStrategy
{
public:
  TextRenderStrategy* newInstance() const override
  {
    return new RenderCountingStrategy;
  }
  void boundingBox(const std::string& string,
                   const Avogadro::Rendering::TextProperties& tprop,
                   int bbox[4]) const override
  {
    m_qt.boundingBox(string, tprop, bbox);
  }
  void render(const std::string& string,
              const Avogadro::Rendering::TextProperties& tprop,
              unsigned char* buffer, const Vector2i& dims) const override
  {
    ++renders;
    m_qt.render(string, tprop, buffer, dims);
  }
  mutable int renders = 0;

private:
  Avogadro::QtOpenGL::QtTextRenderStrategy m_qt;
};

// One drawable of every kind that takes its shader program from the
// renderer's per-context cache, spread over the view.
GeometryNode* makeEveryProgramScene()
{
  auto* geometry = new GeometryNode;

  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(-3, 2, 0), Vector3ub(255, 0, 0), 0.5f);
  geometry->addDrawable(spheres);

  auto* cylinders = new CylinderGeometry;
  cylinders->addCylinder(Vector3f(-1, 2, 0), Vector3f(1, 2, 0), 0.25f,
                         Vector3ub(0, 255, 0));
  geometry->addDrawable(cylinders);

  auto* mesh = new MeshGeometry;
  Avogadro::Core::Array<Vector3f> vertices;
  Avogadro::Core::Array<Vector3f> normals;
  vertices.push_back(Vector3f(2, 1.5f, 0));
  vertices.push_back(Vector3f(3, 1.5f, 0));
  vertices.push_back(Vector3f(2.5f, 2.5f, 0));
  for (int i = 0; i < 3; ++i)
    normals.push_back(Vector3f(0, 0, 1));
  mesh->setColor(Vector3ub(0, 0, 255));
  mesh->addVertices(vertices, normals);
  mesh->addTriangle(0, 1, 2);
  geometry->addDrawable(mesh);

  auto* wide = new WideLineGeometry;
  wide->addLine(Vector3f(-3, 0, 0), Vector3f(-1, 0, 0), Vector3ub(255, 255, 0),
                0.1f);
  geometry->addDrawable(wide);

  auto* strip = new LineStripGeometry;
  Avogadro::Core::Array<Vector3f> stripPoints;
  stripPoints.push_back(Vector3f(0, -0.5f, 0));
  stripPoints.push_back(Vector3f(1, 0.5f, 0));
  stripPoints.push_back(Vector3f(2, -0.5f, 0));
  // glLineWidth() above 1 is an error in a core profile on macOS.
  strip->addLineStrip(stripPoints, Vector3ub(255, 0, 255), 1.0f);
  geometry->addDrawable(strip);

  // DashedLineGeometry is deprecated but still shipped, and still uses a
  // program from the cache.
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  auto* dashed = new DashedLineGeometry;
#if defined(__clang__) || defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
  dashed->addDashedLine(Vector3f(-3, -2, 0), Vector3f(-1, -2, 0),
                        Vector3ub(0, 255, 255), 6);
  geometry->addDrawable(dashed);

  auto* arrow = new ArrowGeometry;
  arrow->addSingleArrow(Vector3f(0, -2, 0), Vector3f(2, -2, 0),
                        Vector3ub(255, 128, 0));
  geometry->addDrawable(arrow);

  auto* label = new TextLabel3D;
  label->setText("Label");
  label->setAnchor(Vector3f(3, -2, 0));
  geometry->addDrawable(label);

  return geometry;
}

class GLWidgetTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    std::string reason;
    widget = sharedWidget(reason);
    if (widget == nullptr)
      GTEST_SKIP() << reason;

    clearScene(*widget);
    widget->makeCurrent();
    auto* geometry = new GeometryNode;
    auto* spheres = new SphereGeometry;
    geometry->addDrawable(spheres);
    spheres->addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 0.5f);
    spheres->addSphere(Vector3f(2, 0, 0), Vector3ub(0, 255, 0), 1.5f);
    spheres->addSphere(Vector3f(0, 2, 1), Vector3ub(0, 0, 255), 1.0f);
    widget->renderer().scene().rootNode().addChild(geometry);
    widget->renderer().scene().setBackgroundColor(Background);
    widget->renderer().solidPipeline().setBackgroundColor(Background);
    widget->renderer().resetGeometry();
    widget->renderer().resetCamera();
    widget->doneCurrent();
    settle();
  }

  // Replace the scene with the node, then return what the widget draws.
  // The caller checks the image is not null.
  QImage showNode(GeometryNode* node)
  {
    clearScene(*widget);
    widget->makeCurrent();
    widget->renderer().scene().rootNode().addChild(node);
    widget->renderer().resetGeometry();
    widget->renderer().resetCamera();
    widget->doneCurrent();
    settle();
    return widget->grabFramebuffer();
  }

  GLWidget* widget = nullptr;
};

// Restores the SolidPipeline effect flags when it goes out of scope.
struct PipelineFlagsGuard
{
  explicit PipelineFlagsGuard(Avogadro::Rendering::SolidPipeline& pipeline)
    : p(pipeline), fog(pipeline.getFogEnabled()), ao(pipeline.getAoEnabled()),
      ed(pipeline.getEdEnabled()), dof(pipeline.getDofEnabled())
  {
  }
  ~PipelineFlagsGuard()
  {
    p.setFogEnabled(fog);
    p.setAoEnabled(ao);
    p.setEdEnabled(ed);
    p.setDofEnabled(dof);
  }
  Avogadro::Rendering::SolidPipeline& p;
  bool fog, ao, ed, dof;
};

// For a test that makes the widget's context current and then uses GL
// objects directly: on exit, restores the default framebuffer, viewport and
// program, and releases the context. Declare it before any GL object so it
// is destroyed last.
struct ContextGuard
{
  explicit ContextGuard(GLWidget* widget) : w(widget)
  {
    if (QOpenGLContext* ctx = QOpenGLContext::currentContext())
      ctx->functions()->glGetIntegerv(GL_VIEWPORT, vp);
  }
  ~ContextGuard()
  {
    if (QOpenGLContext* ctx = QOpenGLContext::currentContext()) {
      ctx->functions()->glBindFramebuffer(GL_FRAMEBUFFER,
                                          w->defaultFramebufferObject());
      ctx->functions()->glViewport(vp[0], vp[1], vp[2], vp[3]);
      ctx->functions()->glUseProgram(0);
    }
    w->doneCurrent();
  }
  GLWidget* w;
  GLint vp[4] = { 0, 0, 0, 0 };
};

} // namespace

TEST_F(GLWidgetTest, becomesValid)
{
  EXPECT_TRUE(widget->isValid()) << widget->error().toStdString();
  EXPECT_NE(widget->context(), nullptr);
}

TEST_F(GLWidgetTest, framebufferSize)
{
  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  const qreal dpr = widget->devicePixelRatioF();
  EXPECT_EQ(image.width(), qRound(widget->width() * dpr));
  EXPECT_EQ(image.height(), qRound(widget->height() * dpr));
}

TEST_F(GLWidgetTest, cornersAreBackground)
{
  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  saveForInspection(image, "glwidget-spheres.png");
  for (const QPoint p : { QPoint(0, 0), QPoint(image.width() - 1, 0),
                          QPoint(0, image.height() - 1),
                          QPoint(image.width() - 1, image.height() - 1) }) {
    const QRgb c = image.pixel(p);
    EXPECT_NEAR(qRed(c), Background[0], 2) << p.x() << "," << p.y();
    EXPECT_NEAR(qGreen(c), Background[1], 2) << p.x() << "," << p.y();
    EXPECT_NEAR(qBlue(c), Background[2], 2) << p.x() << "," << p.y();
  }
}

TEST_F(GLWidgetTest, eachSphereIsDrawnInItsColor)
{
  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());

  // Shading darkens the colors, so look for a dominant channel. The minimum is
  // low enough for the shaded side of a sphere.
  const Bounds red = dominantBounds(image, 0, 90, 60);
  const Bounds green = dominantBounds(image, 1, 90, 60);
  const Bounds blue = dominantBounds(image, 2, 150, 90);
  ASSERT_GT(red.count, 20);
  ASSERT_GT(green.count, 20);
  ASSERT_GT(blue.count, 20);

  // The green sphere (radius 1.5) is the largest, the red one (radius 0.5) the
  // smallest.
  EXPECT_GT(green.count, blue.count);
  EXPECT_GT(blue.count, red.count);
}

TEST_F(GLWidgetTest, spherePositionsFollowTheScene)
{
  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());

  const Bounds red = dominantBounds(image, 0, 90, 60);
  const Bounds green = dominantBounds(image, 1, 90, 60);
  const Bounds blue = dominantBounds(image, 2, 150, 90);
  ASSERT_GT(red.count, 20);
  ASSERT_GT(green.count, 20);
  ASSERT_GT(blue.count, 20);

  // Green is at +x and blue at +y from red (image y grows downward).
  EXPECT_GT(green.centerX(), red.centerX());
  EXPECT_LT(blue.centerY(), red.centerY());

  // Each sphere's colored pixels surround its projected center.
  const struct
  {
    const Bounds& bounds;
    Vector3f center;
    const char* name;
  } spheres[] = { { red, Vector3f(0, 0, 0), "red" },
                  { green, Vector3f(2, 0, 0), "green" },
                  { blue, Vector3f(0, 2, 1), "blue" } };
  for (const auto& s : spheres) {
    const QPointF p = screenPoint(*widget, image, s.center);
    EXPECT_GE(p.x(), s.bounds.minX) << s.name;
    EXPECT_LE(p.x(), s.bounds.maxX + 1) << s.name;
    EXPECT_GE(p.y(), s.bounds.minY) << s.name;
    EXPECT_LE(p.y(), s.bounds.maxY + 1) << s.name;
  }
}

TEST_F(GLWidgetTest, texture2DAppliesDeferredParametersOnUpload)
{
  // Configure parameters before a GL context is current.
  auto texture = std::make_unique<Texture2D>();
  texture->setMinFilter(Texture2D::Nearest);
  texture->setMagFilter(Texture2D::Nearest);
  texture->setWrappingS(Texture2D::ClampToEdge);
  texture->setWrappingT(Texture2D::MirroredRepeat);
  EXPECT_EQ(texture->handle(), 0u);
  EXPECT_FALSE(texture->ready());

  widget->makeCurrent();
  std::vector<unsigned char> pixel = { 255, 128, 64, 255 };
  ASSERT_TRUE(texture->upload(pixel, Vector2i(1, 1), Texture2D::IncomingRGBA,
                              Texture2D::InternalRGBA))
    << texture->error();
  EXPECT_GT(texture->handle(), 0u);
  EXPECT_TRUE(texture->ready());

  ASSERT_TRUE(texture->bind());
  QOpenGLFunctions* gl = QOpenGLContext::currentContext()->functions();
  GLint minFilter = 0, magFilter = 0, wrapS = 0, wrapT = 0;
  gl->glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, &minFilter);
  gl->glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, &magFilter);
  gl->glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, &wrapS);
  gl->glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, &wrapT);
  EXPECT_EQ(minFilter, GL_NEAREST);
  EXPECT_EQ(magFilter, GL_NEAREST);
  EXPECT_EQ(wrapS, GL_CLAMP_TO_EDGE);
  EXPECT_EQ(wrapT, GL_MIRRORED_REPEAT);

  // Updating a parameter after creation updates both cache and GL state.
  texture->setMagFilter(Texture2D::Linear);
  EXPECT_EQ(texture->magFilter(), Texture2D::Linear);
  ASSERT_TRUE(texture->bind());
  gl->glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, &magFilter);
  EXPECT_EQ(magFilter, GL_LINEAR);

  texture->release();
  // Destroy the texture while the GL context is still current.
  texture.reset();
  widget->doneCurrent();
}

TEST_F(GLWidgetTest, hiddenDrawableIsNotRendered)
{
  auto* geometry = new GeometryNode;
  auto* visibleSphere = new SphereGeometry;
  visibleSphere->addSphere(Vector3f(-1.5f, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  auto* hiddenSphere = new SphereGeometry;
  hiddenSphere->addSphere(Vector3f(1.5f, 0, 0), Vector3ub(0, 255, 0), 1.0f);
  hiddenSphere->setVisible(false);
  geometry->addDrawable(visibleSphere);
  geometry->addDrawable(hiddenSphere);

  const QImage image = showNode(geometry);
  ASSERT_FALSE(image.isNull());
  const Bounds red = dominantBounds(image, 0, 90, 60);
  const Bounds green = dominantBounds(image, 1, 90, 60);
  EXPECT_GT(red.count, 20);
  EXPECT_EQ(green.count, 0);
}

TEST_F(GLWidgetTest, curveGeometrySetsOpacityForTranslucentPass)
{
  auto* geometry = new GeometryNode;
  auto* curve = new BSplineGeometry(false);
  curve->setRenderPass(TranslucentPass);
  curve->addPoint(Vector3f(-2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0,
                  0);
  curve->addPoint(Vector3f(0.0f, 0.5f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 1);
  curve->addPoint(Vector3f(2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 2);
  geometry->addDrawable(curve);

  const QImage image = showNode(geometry);
  ASSERT_FALSE(image.isNull());
  // Without CurveGeometry::render() setting opacity = 1.0, alpha defaults to
  // 0.0 and TranslucentPass blending makes the curve completely invisible.
  const Bounds red = dominantBounds(image, 0, 90, 60);
  EXPECT_GT(red.count, 50);
}

TEST_F(GLWidgetTest, arrowGeometryLitFromUpperFront)
{
  auto* geometry = new GeometryNode;
  auto* arrow = new ArrowGeometry;
  arrow->setRadiusScale(4.0f);
  arrow->addSingleArrow(Vector3f(-2.5f, 0.0f, 0.0f), Vector3f(2.5f, 0.0f, 0.0f),
                        Vector3ub(220, 220, 220));
  geometry->addDrawable(arrow);
  widget->renderer().scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
  widget->renderer().solidPipeline().setBackgroundColor(
    Vector4ub(0, 0, 0, 255));

  const QImage image = showNode(geometry);
  ASSERT_FALSE(image.isNull());

  // Check both shaft (x = -0.5) and cone head (x = 1.8): the light is at
  // normalize(0, 1, 1), so the upper half of each section (smaller image y)
  // must be brighter than the lower half.
  for (const float x : { -0.5f, 1.8f }) {
    const QPointF center = screenPoint(*widget, image, Vector3f(x, 0.0f, 0.0f));
    const int cx = qRound(center.x());
    const int cy = qRound(center.y());
    ASSERT_GT(cx, 0);
    ASSERT_LT(cx, image.width());

    double topSum = 0.0;
    int topCount = 0;
    double bottomSum = 0.0;
    int bottomCount = 0;
    for (int y = 0; y < image.height(); ++y) {
      const QRgb px = image.pixel(cx, y);
      const int lum = qRed(px);
      if (lum <= 10)
        continue;
      if (y < cy) {
        topSum += lum;
        ++topCount;
      } else if (y > cy) {
        bottomSum += lum;
        ++bottomCount;
      }
    }
    ASSERT_GT(topCount, 2) << "x=" << x;
    ASSERT_GT(bottomCount, 2) << "x=" << x;
    EXPECT_GT(topSum / topCount, bottomSum / bottomCount) << "x=" << x;
  }
}

TEST_F(GLWidgetTest, shaderProgramSetTextureSamplerReservesUnitZero)
{
  widget->makeCurrent();
  ContextGuard guard(widget);
  Shader vs(Shader::Vertex,
            "#version 400\n"
            "void main() { gl_Position = vec4(0.0, 0.0, 0.0, 1.0); }\n");
  Shader fs(Shader::Fragment,
            "#version 400\n"
            "uniform sampler2D u_tex;\n"
            "out vec4 outColor;\n"
            "void main() { outColor = texture(u_tex, vec2(0.5)); }\n");
  ASSERT_TRUE(vs.compile()) << vs.error();
  ASSERT_TRUE(fs.compile()) << fs.error();

  ShaderProgram program;
  ASSERT_TRUE(program.attachShader(vs));
  ASSERT_TRUE(program.attachShader(fs));
  ASSERT_TRUE(program.link()) << program.error();
  ASSERT_TRUE(program.bind()) << program.error();

  Texture2D texture;
  std::vector<unsigned char> pixel = { 255, 0, 0, 255 };
  ASSERT_TRUE(texture.upload(pixel, Vector2i(1, 1), Texture2D::IncomingRGBA,
                             Texture2D::InternalRGBA))
    << texture.error();
  ASSERT_TRUE(program.setTextureSampler("u_tex", texture)) << program.error();

  QOpenGLFunctions* gl = QOpenGLContext::currentContext()->functions();
  GLint progId = 0;
  gl->glGetIntegerv(GL_CURRENT_PROGRAM, &progId);
  ASSERT_GT(progId, 0);
  const GLint loc = gl->glGetUniformLocation(progId, "u_tex");
  ASSERT_GE(loc, 0);
  GLint unit = -1;
  gl->glGetUniformiv(progId, loc, &unit);
  EXPECT_EQ(unit, 1);
}

TEST_F(GLWidgetTest, solidPipelineBypassRendersOpaqueGeometry)
{
  auto& pipeline = widget->renderer().solidPipeline();
  PipelineFlagsGuard restore(pipeline);

  pipeline.setFogEnabled(false);
  pipeline.setAoEnabled(false);
  pipeline.setEdEnabled(false);
  pipeline.setDofEnabled(false);
  ASSERT_FALSE(pipeline.hasActiveEffects());

  auto* geometry = new GeometryNode;
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(-1.5f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.9f);
  auto* curve = new BSplineGeometry(false);
  curve->addPoint(Vector3f(0.2f, -1.0f, 0.0f), Vector3ub(0, 255, 0), 0.4f, 0,
                  0);
  curve->addPoint(Vector3f(1.2f, 0.0f, 0.0f), Vector3ub(0, 255, 0), 0.4f, 0, 1);
  curve->addPoint(Vector3f(2.2f, 1.0f, 0.0f), Vector3ub(0, 255, 0), 0.4f, 0, 2);
  geometry->addDrawable(spheres);
  geometry->addDrawable(curve);

  // Direct on-screen render (bypassing SolidPipeline's offscreen FBO).
  const QImage window = showNode(geometry);
  ASSERT_FALSE(window.isNull());
  EXPECT_GT(dominantBounds(window, 0, 90, 60).count, 20);
  EXPECT_GT(dominantBounds(window, 1, 90, 60).count, 20);

  // Transparent offscreen render: foreground has opaque alpha, corners stay
  // transparent.
  RenderOptions opts;
  opts.size = QSize(200, 200);
  opts.transparentBackground = true;
  const QImage exported = widget->renderImage(opts);
  ASSERT_FALSE(exported.isNull());
  EXPECT_EQ(qAlpha(exported.pixel(0, 0)), 0);
  const Bounds red = dominantBounds(exported, 0, 90, 60);
  const Bounds green = dominantBounds(exported, 1, 90, 60);
  ASSERT_GT(red.count, 20);
  ASSERT_GT(green.count, 20);
  EXPECT_EQ(
    qAlpha(exported.pixel(qRound(red.centerX()), qRound(red.centerY()))), 255);
  EXPECT_EQ(
    qAlpha(exported.pixel(qRound(green.centerX()), qRound(green.centerY()))),
    255);
}

TEST_F(GLWidgetTest, solidPipelineEarlyOutWorksInPerspectiveAndOrthographic)
{
  auto& pipeline = widget->renderer().solidPipeline();
  PipelineFlagsGuard restoreFlags(pipeline);
  struct RestoreProjection
  {
    GLWidget* w;
    Avogadro::Rendering::Projection proj;
    ~RestoreProjection()
    {
      w->renderer().camera().setProjectionType(proj);
      w->renderer().resetCamera();
    }
  } restoreProjection{ widget, widget->renderer().camera().projectionType() };

  pipeline.setFogEnabled(true);
  pipeline.setAoEnabled(true);
  pipeline.setEdEnabled(true);
  pipeline.setDofEnabled(false);

  for (const auto proj : { Perspective, Orthographic }) {
    SCOPED_TRACE(proj == Perspective ? "perspective" : "orthographic");
    widget->renderer().camera().setProjectionType(proj);
    widget->renderer().resetCamera();
    settle();

    const QImage image = widget->grabFramebuffer();
    ASSERT_FALSE(image.isNull());
    // Corners must stay exact background (depth >= 1.0 early-out).
    const QRgb corner = image.pixel(0, 0);
    EXPECT_NEAR(qRed(corner), Background[0], 2);
    EXPECT_NEAR(qGreen(corner), Background[1], 2);
    EXPECT_NEAR(qBlue(corner), Background[2], 2);
    // All three spheres must remain visibly rendered in their colors.
    EXPECT_GT(dominantBounds(image, 0, 60, 50).count, 10);
    EXPECT_GT(dominantBounds(image, 1, 60, 50).count, 20);
    EXPECT_GT(dominantBounds(image, 2, 100, 80).count, 15);
  }
}

TEST_F(GLWidgetTest, solidPipelineCleanupAndReinitialize)
{
  widget->makeCurrent();
  ContextGuard guard(widget);

  GLRenderer renderer;
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  renderer.resize(64, 64);
  EXPECT_TRUE(renderer.solidPipeline().hasActiveEffects());
  EXPECT_TRUE(renderer.solidPipeline().begin());
  renderer.solidPipeline().end(renderer.camera());

  renderer.cleanup();
  EXPECT_FALSE(renderer.solidPipeline().begin());

  // Re-initializing after cleanup must restore a working pipeline.
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  renderer.resize(64, 64);
  EXPECT_TRUE(renderer.solidPipeline().begin());
  renderer.solidPipeline().end(renderer.camera());
  renderer.cleanup();
}

// Moving a GLWidget to another top-level window makes Qt replace its context.
// The renderer must release the old context's objects (not delete the stale
// names in the new one) and come back usable.
TEST_F(GLWidgetTest, reparentToAnotherWindowKeepsRendering)
{
  QWidget windowA;
  auto* layoutA = new QVBoxLayout(&windowA);
  QWidget windowB;
  auto* layoutB = new QVBoxLayout(&windowB);
  auto* moving = new GLWidget(&windowA);
  layoutA->addWidget(moving);
  windowA.resize(200, 150);
  windowB.resize(200, 150);
  windowA.show();
  settle();
  ASSERT_TRUE(moving->isValid()) << moving->error().toStdString();
  moving->renderer().solidPipeline().setAoEnabled(true);
  EXPECT_FALSE(moving->grabFramebuffer().isNull());

  layoutB->addWidget(moving);
  windowB.show();
  windowA.hide();
  settle();
  ASSERT_TRUE(moving->isValid()) << moving->error().toStdString();
  ASSERT_NE(moving->context(), nullptr);
  moving->makeCurrent();
  drainGLErrors();
  moving->doneCurrent();
  const QImage image = moving->grabFramebuffer();
  EXPECT_FALSE(image.isNull());
  moving->makeCurrent();
  EXPECT_EQ(QOpenGLContext::currentContext()->functions()->glGetError(),
            static_cast<GLenum>(GL_NO_ERROR));
  moving->doneCurrent();
  // Destroy the widget with its window still alive and the renderer clean.
  delete moving;
  settle();
}

// Every drawable type draws with a shader program from the renderer's
// per-context cache, and none of that leaves a GL error behind.
TEST_F(GLWidgetTest, everyProgramRendersWithoutGLErrors)
{
  clearScene(*widget);
  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(makeEveryProgramScene());
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  // A second frame reuses the cached programs and the uploaded buffers.
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();
  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  EXPECT_GT(dominantBounds(image, 0, 90, 60).count, 20); // the red sphere
  EXPECT_GT(dominantBounds(image, 1, 90, 60).count, 20); // the cylinder
}

// The renderer walks the scene once and sorts the drawables by pass: each
// visible drawable renders once, in its own pass, in scene order.
TEST_F(GLWidgetTest, drawablesRenderOnceInTheirPassInSceneOrder)
{
  using namespace Avogadro::Rendering;
  std::vector<int> log;
  auto* outer = new GroupNode;
  auto* first = new GeometryNode;
  auto* inner = new GroupNode;
  auto* second = new GeometryNode;
  auto* hiddenGroup = new GroupNode;
  auto* third = new GeometryNode;
  outer->addChild(first);
  outer->addChild(inner);
  inner->addChild(second);
  hiddenGroup->setVisible(false);
  outer->addChild(hiddenGroup);
  hiddenGroup->addChild(third);

  // Ids are in scene order within each pass; the passes are interleaved.
  first->addDrawable(new CountingDrawable(20, Overlay2DPass, log));
  first->addDrawable(new CountingDrawable(10, TranslucentPass, log));
  first->addDrawable(new CountingDrawable(1, SolidPass, log));
  first->addDrawable(new CountingDrawable(30, NotRendering, log));
  second->addDrawable(new CountingDrawable(11, OpaquePass, log));
  auto* hidden = new CountingDrawable(99, SolidPass, log);
  hidden->setVisible(false);
  second->addDrawable(hidden);
  second->addDrawable(new CountingDrawable(2, SolidPass, log));
  second->addDrawable(new CountingDrawable(15, Overlay3DPass, log));
  third->addDrawable(new CountingDrawable(3, SolidPass, log));
  // Real geometry in other passes next to the counting ones.
  auto* sphere = new SphereGeometry;
  sphere->addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  second->addDrawable(sphere);
  auto* translucent = new SphereGeometry;
  translucent->addSphere(Vector3f(1, 0, 0), Vector3ub(0, 255, 0), 1.0f);
  translucent->setRenderPass(TranslucentPass);
  second->addDrawable(translucent);

  clearScene(*widget);
  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(outer);
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  drainGLErrors();
  log.clear();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  // The hidden drawable and everything under the hidden group (3) are
  // skipped.
  EXPECT_EQ(log, (std::vector<int>{ 1, 2, 11, 10, 15, 20 }));

  // The buckets are reused: a second frame gives the same result.
  log.clear();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  EXPECT_EQ(log, (std::vector<int>{ 1, 2, 11, 10, 15, 20 }));

  // Showing the group again brings its drawable back, in scene order.
  hiddenGroup->setVisible(true);
  log.clear();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  EXPECT_EQ(log, (std::vector<int>{ 1, 2, 3, 11, 10, 15, 20 }));
  widget->doneCurrent();
}

// A label under a hidden node still loses its texture when the text strategy
// changes, so showing it again does not draw a texture from the old strategy.
TEST_F(GLWidgetTest, hiddenLabelsAreResetWhenTheTextStrategyChanges)
{
  using namespace Avogadro::Rendering;
  clearScene(*widget);
  widget->makeCurrent();
  auto* group = new GroupNode;
  auto* geometry = new GeometryNode;
  auto* label = new TextLabel3D;
  label->setText("Hidden");
  label->setAnchor(Vector3f(0, 0, 0));
  geometry->addDrawable(label);
  group->addChild(geometry);
  widget->renderer().scene().rootNode().addChild(group);
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();

  // Build the texture with the widget's own strategy.
  widget->renderer().render();

  RenderCountingStrategy* counting = new RenderCountingStrategy;
  group->setVisible(false);
  widget->renderer().setTextRenderStrategy(counting);
  widget->renderer().render();
  EXPECT_EQ(counting->renders, 0);

  // The label was reset although it was hidden, so it is rasterized again.
  group->setVisible(true);
  widget->renderer().render();
  EXPECT_GT(counting->renders, 0);

  // Leave the shared widget with a normal strategy.
  widget->renderer().setTextRenderStrategy(
    new Avogadro::QtOpenGL::QtTextRenderStrategy);
  widget->doneCurrent();
}

// cleanup() deletes the cached programs; initialize() on the same context
// must rebuild them on demand.
TEST_F(GLWidgetTest, cleanupThenInitializeRendersAgain)
{
  clearScene(*widget);
  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(makeEveryProgramScene());
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));

  widget->renderer().cleanup();
  widget->renderer().initialize();
  ASSERT_TRUE(widget->renderer().isValid()) << widget->renderer().error();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();

  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  EXPECT_GT(dominantBounds(image, 0, 90, 60).count, 20);
  EXPECT_GT(dominantBounds(image, 1, 90, 60).count, 20);
}

// A drawable rendered directly, outside GLRenderer::render(), builds its
// program in a temporary context and deletes it again.
TEST_F(GLWidgetTest, drawableRendersOutsideTheRenderer)
{
  widget->makeCurrent();
  drainGLErrors();
  {
    SphereGeometry spheres;
    spheres.addSphere(Vector3f(0, 0, -5), Vector3ub(255, 255, 255), 1.0f);
    Camera camera;
    camera.calculatePerspective(40.0f, 0.1f, 100.0f);
    spheres.render(camera);
    EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
    // Again: the first call's program is gone, so this builds a new one.
    spheres.render(camera);
    EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  }
  widget->doneCurrent();
}

// abandon() forgets the GL name without deleting it: the object can be
// uploaded or bound again, and the old name is still alive in this context.
TEST_F(GLWidgetTest, abandonForgetsGLObjectsWithoutDeletingThem)
{
  widget->makeCurrent();
  ContextGuard guard(widget);
  drainGLErrors();
  QOpenGLContext* context = QOpenGLContext::currentContext();
  QOpenGLFunctions* gl = context->functions();
  QOpenGLExtraFunctions* extra = context->extraFunctions();

  BufferObject buffer;
  const std::vector<float> data = { 1.0f, 2.0f, 3.0f };
  ASSERT_TRUE(buffer.upload(data, BufferObject::ArrayBuffer));
  const auto oldBuffer = static_cast<GLuint>(buffer.handle());
  ASSERT_NE(oldBuffer, 0u);
  buffer.abandon();
  EXPECT_FALSE(buffer.ready());
  EXPECT_EQ(buffer.handle(), 0u);
  EXPECT_EQ(gl->glIsBuffer(oldBuffer), GL_TRUE);
  ASSERT_TRUE(buffer.upload(data, BufferObject::ArrayBuffer));
  EXPECT_TRUE(buffer.ready());
  EXPECT_NE(static_cast<GLuint>(buffer.handle()), oldBuffer);
  gl->glDeleteBuffers(1, &oldBuffer);

  VertexArrayObject vao;
  ASSERT_TRUE(vao.bind());
  vao.release();
  auto oldVao = static_cast<GLuint>(vao.handle());
  ASSERT_NE(oldVao, 0u);
  vao.abandon();
  EXPECT_EQ(vao.handle(), 0u);
  EXPECT_EQ(extra->glIsVertexArray(oldVao), GL_TRUE);
  ASSERT_TRUE(vao.bind());
  vao.release();
  EXPECT_NE(static_cast<GLuint>(vao.handle()), oldVao);
  extra->glDeleteVertexArrays(1, &oldVao);

  Texture2D texture;
  const std::vector<unsigned char> pixels(4 * 4, 255);
  ASSERT_TRUE(texture.upload(pixels, Vector2i(2, 2), Texture2D::IncomingRGBA,
                             Texture2D::InternalRGBA));
  auto oldTexture = static_cast<GLuint>(texture.handle());
  ASSERT_NE(oldTexture, 0u);
  texture.abandon();
  EXPECT_FALSE(texture.ready());
  EXPECT_EQ(texture.handle(), 0u);
  EXPECT_EQ(gl->glIsTexture(oldTexture), GL_TRUE);
  ASSERT_TRUE(texture.upload(pixels, Vector2i(2, 2), Texture2D::IncomingRGBA,
                             Texture2D::InternalRGBA));
  EXPECT_NE(static_cast<GLuint>(texture.handle()), oldTexture);
  gl->glDeleteTextures(1, &oldTexture);

  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
}

// A curve keeps its GL objects in its Line structs. After the renderer's
// context life ends and a new one starts, the curve forgets the old buffers
// (it never deletes them) and builds new ones.
TEST_F(GLWidgetTest, curveGeometryRebuildsAfterContextReplaced)
{
  clearScene(*widget);
  widget->makeCurrent();
  auto* geometry = new GeometryNode;
  auto* curve = new BSplineGeometry(false);
  curve->addPoint(Vector3f(-2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0,
                  0);
  curve->addPoint(Vector3f(0.0f, 0.5f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 1);
  curve->addPoint(Vector3f(2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 2);
  geometry->addDrawable(curve);
  widget->renderer().scene().rootNode().addChild(geometry);
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  ASSERT_EQ(curve->lines().size(), 1u);
  const auto oldVbo = static_cast<GLuint>(curve->lines()[0]->vbo.handle());
  ASSERT_NE(oldVbo, 0u);

  widget->renderer().cleanup();
  widget->renderer().initialize();
  ASSERT_TRUE(widget->renderer().isValid()) << widget->renderer().error();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  const auto newVbo = static_cast<GLuint>(curve->lines()[0]->vbo.handle());
  EXPECT_NE(newVbo, 0u);
  // The old name was abandoned, not deleted, so it is still alive here.
  EXPECT_NE(newVbo, oldVbo);
  QOpenGLContext* context = QOpenGLContext::currentContext();
  EXPECT_EQ(context->functions()->glIsBuffer(oldVbo), GL_TRUE);
  context->functions()->glDeleteBuffers(1, &oldVbo);
  widget->doneCurrent();
  settle();

  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  EXPECT_GT(dominantBounds(image, 0, 90, 60).count, 50);
}

// The main camera and the 2D overlay camera share one uniform buffer: a
// drawable rendered with the overlay camera must land where that camera puts
// it, and the main scene must stay put in the frames before and after.
TEST_F(GLWidgetTest, overlayDrawableUsesItsOwnCamera)
{
  using namespace Avogadro::Rendering;
  // A gray quad (flat 0.4 * 255 shading) in overlay coordinates: logical
  // pixels, origin at the bottom left.
  const float left = 20.0f, right = 100.0f, bottom = 30.0f, top = 70.0f;
  auto* node = new GeometryNode;
  auto* quad = new MeshGeometry;
  Avogadro::Core::Array<Vector3f> vertices;
  Avogadro::Core::Array<Vector3f> normals;
  vertices.push_back(Vector3f(left, bottom, 0));
  vertices.push_back(Vector3f(right, bottom, 0));
  vertices.push_back(Vector3f(right, top, 0));
  vertices.push_back(Vector3f(left, top, 0));
  for (int i = 0; i < 4; ++i)
    normals.push_back(Vector3f(0, 0, 1));
  quad->setColor(Vector3ub(255, 255, 255));
  quad->addVertices(vertices, normals);
  // Both windings, so the quad shows whatever the face culling is.
  quad->addTriangle(0, 1, 2);
  quad->addTriangle(0, 2, 3);
  quad->addTriangle(0, 2, 1);
  quad->addTriangle(0, 3, 2);
  quad->setRenderPass(Overlay2DPass);
  node->addDrawable(quad);

  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(node);
  widget->doneCurrent();
  settle();

  const QImage first = widget->grabFramebuffer();
  ASSERT_FALSE(first.isNull());
  saveForInspection(first, "glwidget-overlay.png");

  // The overlay quad, where the overlay camera puts it.
  const Camera& camera = widget->renderer().camera();
  const double sx = static_cast<double>(first.width()) / camera.width();
  const double sy = static_cast<double>(first.height()) / camera.height();
  const Bounds gray = colorBounds(first, 102, 102, 102, 6);
  ASSERT_GT(gray.count, 100);
  EXPECT_NEAR(gray.minX, left * sx, 2.0 * sx);
  EXPECT_NEAR(gray.maxX + 1, right * sx, 2.0 * sx);
  EXPECT_NEAR(gray.minY, first.height() - top * sy, 2.0 * sy);
  EXPECT_NEAR(gray.maxY + 1, first.height() - bottom * sy, 2.0 * sy);

  // The spheres of the main camera are where the scene puts them.
  const Bounds red = dominantBounds(first, 0, 90, 60);
  ASSERT_GT(red.count, 20);
  const QPointF redCenter = screenPoint(*widget, first, Vector3f(0, 0, 0));
  EXPECT_GE(redCenter.x(), red.minX);
  EXPECT_LE(redCenter.x(), red.maxX + 1);
  EXPECT_GE(redCenter.y(), red.minY);
  EXPECT_LE(redCenter.y(), red.maxY + 1);

  // The next frame starts from the overlay camera in the buffer, and
  // renders the same picture.
  widget->makeCurrent();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();
  const QImage second = widget->grabFramebuffer();
  ASSERT_FALSE(second.isNull());
  EXPECT_EQ(first, second);
}

// A drawable rendered outside GLRenderer::render() with a camera of its own
// lands where that camera puts it, also right after the renderer drew a frame
// with a different camera, and the renderer is unharmed afterwards.
TEST_F(GLWidgetTest, standaloneDrawableUsesTheCameraItIsGiven)
{
  const QImage before = widget->grabFramebuffer();
  ASSERT_FALSE(before.isNull());

  widget->makeCurrent();
  ContextGuard guard(widget);
  QOpenGLFunctions* gl = QOpenGLContext::currentContext()->functions();
  gl->glBindFramebuffer(GL_FRAMEBUFFER, widget->defaultFramebufferObject());
  GLint viewport[4] = { 0, 0, 0, 0 };
  gl->glGetIntegerv(GL_VIEWPORT, viewport);
  const int width = viewport[2];
  const int height = viewport[3];
  ASSERT_GT(width, 0);
  ASSERT_GT(height, 0);

  SphereGeometry sphere;
  sphere.addSphere(Vector3f(0, 0, 0), Vector3ub(255, 255, 255), 1.0f);

  // The eye-space position of the sphere's center decides where it lands in
  // this orthographic view, which spans -5..5 in x and y.
  auto pixelAt = [&](float ndcX) {
    unsigned char rgba[4] = { 0, 0, 0, 0 };
    const int x = static_cast<int>((0.5f + 0.5f * ndcX) * width);
    gl->glReadPixels(x, height / 2, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
    return Vector3ub(rgba[0], rgba[1], rgba[2]);
  };
  auto drawAt = [&](float eyeX) {
    Camera camera;
    camera.setViewport(width, height);
    camera.calculateOrthographic(-5.0f, 5.0f, -5.0f, 5.0f, -10.0f, 10.0f);
    camera.translate(Vector3f(eyeX, 0.0f, -5.0f));
    gl->glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
    gl->glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    gl->glEnable(GL_DEPTH_TEST);
    drainGLErrors();
    sphere.render(camera);
    EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  };
  auto isLit = [](const Vector3ub& c) { return c[0] > 100 && c[1] > 100; };

  drawAt(2.0f); // ndc x = 0.4
  EXPECT_TRUE(isLit(pixelAt(0.4f)));
  EXPECT_FALSE(isLit(pixelAt(0.0f)));
  EXPECT_FALSE(isLit(pixelAt(-0.4f)));
  drawAt(-2.0f); // A different camera: ndc x = -0.4
  EXPECT_TRUE(isLit(pixelAt(-0.4f)));
  EXPECT_FALSE(isLit(pixelAt(0.4f)));
  gl->glDisable(GL_DEPTH_TEST);

  // The renderer still draws its scene with its own camera.
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();
  const QImage after = widget->grabFramebuffer();
  ASSERT_FALSE(after.isNull());
  EXPECT_EQ(before, after);
}

// The camera buffer belongs to the GL context: after cleanup() and
// initialize() it is made again and the overlay and main cameras still work.
TEST_F(GLWidgetTest, cameraBufferIsRecreatedAfterCleanupAndInitialize)
{
  using namespace Avogadro::Rendering;
  auto* node = new GeometryNode;
  auto* spheres = new SphereGeometry;
  spheres->addSphere(Vector3f(40, 40, 0), Vector3ub(255, 255, 255), 0.5f);
  spheres->setRenderPass(Overlay2DPass);
  node->addDrawable(spheres);
  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(node);
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();
  const QImage first = widget->grabFramebuffer();
  ASSERT_FALSE(first.isNull());

  widget->makeCurrent();
  widget->renderer().cleanup();
  widget->renderer().initialize();
  ASSERT_TRUE(widget->renderer().isValid()) << widget->renderer().error();
  drainGLErrors();
  widget->renderer().render();
  EXPECT_EQ(currentGLError(), static_cast<GLenum>(GL_NO_ERROR));
  widget->doneCurrent();
  settle();
  const QImage second = widget->grabFramebuffer();
  ASSERT_FALSE(second.isNull());
  EXPECT_EQ(first, second);
  EXPECT_GT(dominantBounds(second, 0, 90, 60).count, 20);
}
