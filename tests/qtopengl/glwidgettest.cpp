/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/cube.h>
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
#include <avogadro/rendering/volumegeometry.h>
#include <avogadro/rendering/widelinegeometry.h>

#include <QtGui/QImage>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLExtraFunctions>
#include <QtGui/QOpenGLFunctions>
#include <QtOpenGL/QOpenGLFramebufferObject>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

#include <algorithm>
#include <cmath>
#include <memory>
#include <string>
#include <vector>

using Avogadro::Vector2i;
using Avogadro::Vector3;
using Avogadro::Vector3f;
using Avogadro::Vector3i;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Cube;
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
using Avogadro::Rendering::VolumeGeometry;
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

// A scene holding only a VolumeGeometry, seen from +z at a fixed distance. The
// scene is empty apart from the volume, so GLRenderer's clip planes are the
// same for every test using it: the scene radius is 4 + 2 = 6, so the near
// plane is at 2 and the far plane at eyeDistance + 6 along the view axis (for
// the orthographic projection the near plane is at -far, behind the eye). With
// the default eye distance of 12 the far plane is therefore at world z = -6.
//
// It uses the plain framebuffer path (no fog, AO, edge detection or depth of
// field), restores the pipeline flags and the projection type on destruction,
// and any Cube must be declared before it: the cubes must outlive the
// VolumeGeometry.
struct VolumeRig
{
  static constexpr float EyeDistance = 12.0f;
  static constexpr float FarPlaneZ = EyeDistance - (EyeDistance + 6.0f);

  explicit VolumeRig(GLWidget& glWidget, const Cube* cube = nullptr)
    : widget(glWidget), flags(glWidget.renderer().solidPipeline()),
      projection(glWidget.renderer().camera().projectionType())
  {
    auto& pipeline = widget.renderer().solidPipeline();
    pipeline.setFogEnabled(false);
    pipeline.setAoEnabled(false);
    pipeline.setEdEnabled(false);
    pipeline.setDofEnabled(false);

    clearScene(widget);
    widget.makeCurrent();
    auto* geometry = new GeometryNode;
    volume = new VolumeGeometry;
    if (cube != nullptr)
      volume->setCube(*cube);
    volume->setPositiveColor(Vector3ub(255, 0, 0));
    volume->setNegativeColor(Vector3ub(0, 0, 255));
    volume->setRenderPass(TranslucentPass);
    geometry->addDrawable(volume);
    widget.renderer().scene().rootNode().addChild(geometry);
    widget.renderer().scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
    widget.renderer().solidPipeline().setBackgroundColor(
      Vector4ub(0, 0, 0, 255));
    widget.renderer().resetGeometry();
    widget.doneCurrent();
    setView(Perspective, EyeDistance);
  }

  ~VolumeRig()
  {
    clearScene(widget);
    widget.renderer().camera().setProjectionType(projection);
    widget.renderer().resetCamera();
  }

  VolumeRig(const VolumeRig&) = delete;
  VolumeRig& operator=(const VolumeRig&) = delete;

  // The eye is on the +z axis, looking toward -z at the origin.
  void setView(Avogadro::Rendering::Projection type, float eyeDistance)
  {
    widget.renderer().camera().setProjectionType(type);
    widget.renderer().camera().setIdentity();
    widget.renderer().camera().translate(Vector3f(0.0f, 0.0f, -eyeDistance));
  }

  // Draw a frame and grab it. glError is the first GL error raised meanwhile.
  QImage render()
  {
    widget.makeCurrent();
    drainGLErrors();
    widget.doneCurrent();
    settle();
    const QImage image = widget.grabFramebuffer();
    widget.makeCurrent();
    glError = widget.context()->functions()->glGetError();
    drainGLErrors();
    widget.doneCurrent();
    return image;
  }

  // The pixel under a scene point; needs a frame rendered with this camera.
  QRgb pixelAt(const QImage& image, const Vector3f& scenePoint)
  {
    const QPointF p = screenPoint(widget, image, scenePoint);
    return image.pixel(std::clamp(qRound(p.x()), 0, image.width() - 1),
                       std::clamp(qRound(p.y()), 0, image.height() - 1));
  }

  GLWidget& widget;
  PipelineFlagsGuard flags;
  Avogadro::Rendering::Projection projection;
  VolumeGeometry* volume = nullptr;
  GLenum glError = GL_NO_ERROR;
};

// A box [lo, hi] with the given number of points per axis filled with value.
Cube makeUniformCube(const Vector3& lo, const Vector3& hi, int n, float value)
{
  Cube cube;
  cube.setLimits(lo, hi, Vector3i(n, n, n));
  cube.setData(std::vector<float>(static_cast<size_t>(n) * n * n, value));
  return cube;
}

// Shows that a pixel is red volume rather than background.
bool isRedVolume(QRgb px)
{
  return qRed(px) > 40 && qBlue(px) < 20;
}
bool isBlueVolume(QRgb px)
{
  return qBlue(px) > 40 && qRed(px) < 20;
}
bool isBackground(QRgb px)
{
  return qRed(px) < 3 && qGreen(px) < 3 && qBlue(px) < 3;
}

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

TEST_F(GLWidgetTest, volumeGeometryRendersUnderZoomAndNearFarClipping)
{
  // Build a large uniform positive-density cube spanning [-7, 7]^3 around a
  // tiny central sphere (radius 0.2) so GLRenderer's far plane (~distance + 6)
  // and near plane (2.0) both clip the cube when zoomed in and rotated.
  Cube cube;
  constexpr int n = 12;
  cube.setLimits(Vector3(-7.0, -7.0, -7.0), Vector3(7.0, 7.0, 7.0),
                 Vector3i(n, n, n));
  std::vector<float> data(static_cast<size_t>(n * n * n), 0.25f);
  cube.setData(data);

  struct RestoreState
  {
    GLWidget* w;
    Avogadro::Rendering::Projection proj;
    ~RestoreState()
    {
      clearScene(*w);
      w->renderer().camera().setProjectionType(proj);
      w->renderer().resetCamera();
    }
  } restore{ widget, widget->renderer().camera().projectionType() };

  clearScene(*widget);
  widget->makeCurrent();
  auto* geometry = new GeometryNode;
  auto* sphere = new SphereGeometry;
  sphere->addSphere(Vector3f(0.0f, 0.0f, 0.0f), Vector3ub(200, 200, 200), 0.1f);
  auto* volume = new VolumeGeometry;
  volume->setCube(cube);
  volume->setPositiveColor(Vector3ub(255, 0, 0));
  volume->setNegativeColor(Vector3ub(0, 0, 255));
  volume->setRenderPass(TranslucentPass);
  geometry->addDrawable(sphere);
  geometry->addDrawable(volume);
  widget->renderer().scene().rootNode().addChild(geometry);
  widget->renderer().scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
  widget->renderer().solidPipeline().setBackgroundColor(
    Vector4ub(0, 0, 0, 255));
  widget->renderer().resetGeometry();
  widget->doneCurrent();

  for (const auto proj : { Perspective, Orthographic }) {
    SCOPED_TRACE(proj == Perspective ? "perspective" : "orthographic");
    widget->renderer().camera().setProjectionType(proj);
    widget->renderer().resetCamera();
    // Rotate and zoom close so both near and far planes intersect the cube.
    widget->renderer().camera().rotate(0.45f, Vector3f::UnitX());
    widget->renderer().camera().rotate(0.35f, Vector3f::UnitY());
    if (proj == Perspective)
      widget->renderer().camera().preTranslate(Vector3f(0.0f, 0.0f, 8.0f));
    else
      widget->renderer().camera().scale(0.5f);
    settle();

    const QImage image = widget->grabFramebuffer();
    ASSERT_FALSE(image.isNull());

    // Sample a vertical column slightly offset from the tiny center sphere:
    // every sample across the central band must show red volume (no clipped
    // triangular or rectangular hole).
    const int x = image.width() / 2 + image.width() / 8;
    for (int frac = 30; frac <= 70; frac += 10) {
      const int y = (image.height() * frac) / 100;
      const QRgb px = image.pixel(x, y);
      EXPECT_GT(qRed(px), 40) << "missing volume at y=" << y;
      EXPECT_LT(qBlue(px), 20) << "unexpected blue at y=" << y;
    }
  }
}

TEST_F(GLWidgetTest, volumeGeometryOccludedByOpaqueSphere)
{
  // Uniform positive red cube covering z in [-3, 1].
  Cube cube;
  constexpr int n = 8;
  cube.setLimits(Vector3(-3.0, -3.0, -3.0), Vector3(3.0, 3.0, 1.0),
                 Vector3i(n, n, n));
  std::vector<float> data(static_cast<size_t>(n * n * n), 0.4f);
  cube.setData(data);

  auto& pipeline = widget->renderer().solidPipeline();
  struct RestoreState
  {
    GLWidget* w;
    bool fog, ao, ed, dof;
    ~RestoreState()
    {
      clearScene(*w);
      auto& p = w->renderer().solidPipeline();
      p.setFogEnabled(fog);
      p.setAoEnabled(ao);
      p.setEdEnabled(ed);
      p.setDofEnabled(dof);
    }
  } restore{ widget, pipeline.getFogEnabled(), pipeline.getAoEnabled(),
             pipeline.getEdEnabled(), pipeline.getDofEnabled() };

  auto renderWithSphereAtZ = [&](float sphereZ, bool useSolidPipeline,
                                 bool includeVolume) {
    pipeline.setFogEnabled(useSolidPipeline);
    pipeline.setAoEnabled(false);
    pipeline.setEdEnabled(false);
    pipeline.setDofEnabled(false);

    clearScene(*widget);
    widget->makeCurrent();
    auto* geometry = new GeometryNode;
    auto* sphere = new SphereGeometry;
    sphere->addSphere(Vector3f(0.0f, 0.0f, sphereZ), Vector3ub(0, 220, 0),
                      0.8f);
    geometry->addDrawable(sphere);
    if (includeVolume) {
      auto* volume = new VolumeGeometry;
      volume->setCube(cube);
      volume->setPositiveColor(Vector3ub(255, 0, 0));
      volume->setNegativeColor(Vector3ub(0, 0, 255));
      volume->setRenderPass(TranslucentPass);
      geometry->addDrawable(volume);
    }
    widget->renderer().scene().rootNode().addChild(geometry);
    widget->renderer().scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
    widget->renderer().solidPipeline().setBackgroundColor(
      Vector4ub(0, 0, 0, 255));
    widget->renderer().resetGeometry();
    // Fixed camera along +Z looking toward the origin.
    widget->renderer().camera().setIdentity();
    widget->renderer().camera().translate(Vector3f(0.0f, 0.0f, -12.0f));
    widget->doneCurrent();
    settle();

    return widget->grabFramebuffer();
  };

  for (const bool useSolidPipeline : { true, false }) {
    SCOPED_TRACE(useSolidPipeline ? "solid-pipeline" : "bypass");
    // Reference sphere without volume (accounts for white specular highlight
    // and SolidPipeline fog offset).
    const QImage refImg = renderWithSphereAtZ(2.5f, useSolidPipeline, false);
    ASSERT_FALSE(refImg.isNull());
    const QRgb refCenter =
      refImg.pixel(refImg.width() / 2, refImg.height() / 2);

    // Sphere strictly in front of the cube (z = +2.5 vs cube z <= +1.0):
    // must completely occlude the red volume behind it.
    const QImage frontImg = renderWithSphereAtZ(2.5f, useSolidPipeline, true);
    ASSERT_FALSE(frontImg.isNull());
    const QRgb frontCenter =
      frontImg.pixel(frontImg.width() / 2, frontImg.height() / 2);
    EXPECT_GT(qGreen(frontCenter), 100);
    EXPECT_NEAR(qRed(frontCenter), qRed(refCenter), 2);
    // Away from the sphere (inside the cube at x = 2.0), the red volume must
    // still be visible.
    const QPointF sidePt =
      screenPoint(*widget, frontImg, Vector3f(2.0f, 0.0f, -1.0f));
    const QRgb sidePx = frontImg.pixel(qRound(sidePt.x()), qRound(sidePt.y()));
    EXPECT_GT(qRed(sidePx), 80);

    // Sphere strictly behind the cube (z = -4.5 vs cube z >= -3.0):
    // red volume in front of it must tint the sphere strongly red.
    const QImage backImg = renderWithSphereAtZ(-4.5f, useSolidPipeline, true);
    ASSERT_FALSE(backImg.isNull());
    const QRgb backCenter =
      backImg.pixel(backImg.width() / 2, backImg.height() / 2);
    EXPECT_GT(qRed(backCenter), qRed(refCenter) + 80);
  }
}

TEST_F(GLWidgetTest, volumeGeometryDrawsNothingAfterInvalidCube)
{
  // A cube that cannot be uploaded must not leave the previous cube's texture
  // on screen. Two ways to fail: no data at all, and a grid larger than the
  // driver's 3D texture limit (the upload raises GL_INVALID_VALUE).
  const Cube good =
    makeUniformCube(Vector3(-3, -3, -3), Vector3(3, 3, 3), 8, 0.4f);
  const Cube empty;
  widget->makeCurrent();
  GLint maxSize = 0;
  widget->context()->functions()->glGetIntegerv(GL_MAX_3D_TEXTURE_SIZE,
                                                &maxSize);
  widget->doneCurrent();
  // Only the x axis is long, so the data stays small (a few hundred KB).
  Cube tooBig;
  const bool haveTooBig =
    maxSize > 0 && maxSize < 100000 &&
    tooBig.setLimits(Vector3(-3, -3, -3), Vector3(3, 3, 3),
                     Vector3i(maxSize + 1, 2, 2));

  VolumeRig rig(*widget, &good);
  QImage image = rig.render();
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
  EXPECT_TRUE(isRedVolume(rig.pixelAt(image, Vector3f(0, 0, 0))));

  const Cube* invalid[] = { &empty, haveTooBig ? &tooBig : nullptr };
  for (const Cube* bad : invalid) {
    if (bad == nullptr)
      continue;
    SCOPED_TRACE(bad == &empty ? "empty cube" : "oversized cube");
    rig.volume->setCube(*bad);
    image = rig.render();
    ASSERT_FALSE(image.isNull());
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    // No stale volume anywhere near the center of the old cube.
    for (const Vector3f p :
         { Vector3f(0, 0, 0), Vector3f(-1.5f, 1.0f, 0), Vector3f(1.5f, -1, 1) })
      EXPECT_TRUE(isBackground(rig.pixelAt(image, p)));

    // Back to a valid cube: the volume is drawn again.
    rig.volume->setCube(good);
    image = rig.render();
    ASSERT_FALSE(image.isNull());
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    EXPECT_TRUE(isRedVolume(rig.pixelAt(image, Vector3f(0, 0, 0))));
  }

  // clear() removes the cube too.
  rig.volume->clear();
  image = rig.render();
  ASSERT_FALSE(image.isNull());
  EXPECT_TRUE(isBackground(rig.pixelAt(image, Vector3f(0, 0, 0))));
}

TEST_F(GLWidgetTest, volumeGeometryStopsAtFarClipPlane)
{
  // VolumeRig puts the eye at z = 12 with the far plane at z = -6. A faint
  // uniform volume (low alpha, so the ray never saturates) spans z in
  // [-15, 3], which is 9 units past the far plane. Grid nodes are 1 apart, so
  // node 9 sits exactly on the far plane; the second cube is zero beyond it
  // and so equals the first cube cut at the far plane. If rays ran on to the
  // back of the box the first cube would be clearly brighter (about 0.65
  // instead of 0.4 alpha at the center). Rendering is identical sample for
  // sample, so a small tolerance only covers float rounding.
  constexpr int nxy = 5;
  constexpr int nz = 19;
  auto makeCube = [&](int firstNonZeroNode) {
    Cube cube;
    cube.setLimits(Vector3(-3, -3, -15), Vector3(3, 3, 3),
                   Vector3i(nxy, nxy, nz));
    std::vector<float> data(static_cast<size_t>(nxy) * nxy * nz, 0.0f);
    for (int x = 0; x < nxy; ++x)
      for (int y = 0; y < nxy; ++y)
        for (int z = firstNonZeroNode; z < nz; ++z)
          data[static_cast<size_t>(z + nz * (y + nxy * x))] = 0.5f;
    cube.setData(data);
    return cube;
  };
  const Cube full = makeCube(0);
  const Cube cutAtFar = makeCube(9); // z = -6 and nearer
  Cube beyondFar = makeCube(0);      // density only at z <= -8
  {
    std::vector<float> data(static_cast<size_t>(nxy) * nxy * nz, 0.0f);
    for (int x = 0; x < nxy; ++x)
      for (int y = 0; y < nxy; ++y)
        for (int z = 0; z <= 7; ++z)
          data[static_cast<size_t>(z + nz * (y + nxy * x))] = 0.5f;
    beyondFar.setData(data);
  }

  VolumeRig rig(*widget, &full);
  rig.volume->setAlphaScale(0.015f);

  for (const auto proj : { Perspective, Orthographic }) {
    SCOPED_TRACE(proj == Perspective ? "perspective" : "orthographic");
    rig.setView(proj, VolumeRig::EyeDistance);

    rig.volume->setCube(full);
    const QImage fullImage = rig.render();
    ASSERT_FALSE(fullImage.isNull());
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    // Check the setup the comment above relies on.
    EXPECT_NEAR(widget->renderer().camera().farPlane(), 18.0f, 0.01f);
    const QRgb fullPx = rig.pixelAt(fullImage, Vector3f(0, 0, 0));

    rig.volume->setCube(cutAtFar);
    const QImage cutImage = rig.render();
    ASSERT_FALSE(cutImage.isNull());
    const QRgb cutPx = rig.pixelAt(cutImage, Vector3f(0, 0, 0));

    // The volume must be clearly visible, or the comparison means nothing.
    EXPECT_GT(qRed(cutPx), 60);
    EXPECT_LT(qRed(cutPx), 200);
    EXPECT_NEAR(qRed(fullPx), qRed(cutPx), 3);

    // Density only past the far plane contributes nothing at all.
    rig.volume->setCube(beyondFar);
    const QImage beyondImage = rig.render();
    ASSERT_FALSE(beyondImage.isNull());
    EXPECT_TRUE(isBackground(rig.pixelAt(beyondImage, Vector3f(0, 0, 0))));
  }
}

TEST_F(GLWidgetTest, volumeGeometryOpaqueDepthKeepsStepAnchoring)
{
  // A green opaque sphere (radius 0.8) slides through a faint volume spanning
  // z in [-6, 3], seen from z = 12. The red tint over the sphere's center
  // pixel measures the volume in front of the sphere, from its front surface
  // at z + 0.8 up to z = 3.
  //
  // Uniform density: the tint must match the compositing of full steps plus
  // one partial step. Striped density, with a stripe period (two nodes) about
  // one reference step: as the sphere moves away the tint may only grow, and
  // by a bounded amount per move, because full steps keep their sample
  // positions and only the last one is shortened. Re-spacing all samples over
  // the shortened ray made the tint swing by 0.1 or more and fall while the
  // sphere receded.
  constexpr int nxy = 5;
  // 201 nodes over 7.6 units: the node spacing (0.038) is half the reference
  // step of the striped cube (0.083 / 2 = 0.041), so its stripes have about
  // the period of a step and beat against any change in step spacing.
  constexpr int nz = 201;
  constexpr float density = 0.6f;
  constexpr float alphaScale = 0.03f;
  Cube uniform =
    makeUniformCube(Vector3(-3, -3, -6), Vector3(3, 3, 3), 8, density);
  Cube striped;
  striped.setLimits(Vector3(-3, -3, -4.6), Vector3(3, 3, 3),
                    Vector3i(nxy, nxy, nz));
  {
    std::vector<float> data(static_cast<size_t>(nxy) * nxy * nz);
    for (int x = 0; x < nxy; ++x)
      for (int y = 0; y < nxy; ++y)
        for (int z = 0; z < nz; ++z)
          data[static_cast<size_t>(z + nz * (y + nxy * x))] =
            (z % 2 == 0) ? 0.2f : 1.0f;
    striped.setData(data);
  }

  VolumeRig rig(*widget, &uniform);
  rig.volume->setAlphaScale(alphaScale);
  auto* sphereNode = new GeometryNode;
  auto* spheres = new SphereGeometry;
  sphereNode->addDrawable(spheres);
  widget->makeCurrent();
  widget->renderer().scene().rootNode().addChild(sphereNode);
  widget->doneCurrent();

  // Opacity (0 to 1) of the volume over the sphere's center pixel, found from
  // red = 255 * a + reference * (1 - a), with the reference taken from the
  // same sphere drawn without the volume (it has specular highlights).
  auto tintAt = [&](float sphereZ) {
    spheres->clear();
    spheres->addSphere(Vector3f(0, 0, sphereZ), Vector3ub(0, 220, 0), 0.8f);
    widget->makeCurrent();
    widget->renderer().scene().setDirty(true);
    widget->doneCurrent();
    rig.volume->setAlphaScale(0.0f);
    const QImage ref = rig.render();
    rig.volume->setAlphaScale(alphaScale);
    const QImage img = rig.render();
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    const double r0 = qRed(rig.pixelAt(ref, Vector3f(0, 0, sphereZ + 0.8f)));
    const double r1 = qRed(rig.pixelAt(img, Vector3f(0, 0, sphereZ + 0.8f)));
    return (r1 - r0) / (255.0 - r0);
  };

  // Uniform volume against the compositing formula.
  rig.volume->setCube(uniform);
  const double refStep = std::sqrt(6.0 * 6.0 * 2 + 9.0 * 9.0) / 150.0;
  const double stepAlpha = density * alphaScale;
  for (const float z : { -1.5f, -0.5f, 0.5f }) {
    SCOPED_TRACE(z);
    const double length = 3.0 - (z + 0.8);
    const double expected = 1.0 - std::pow(1.0 - stepAlpha, length / refStep);
    // A partial last step is weighted linearly rather than as a power, which
    // is a difference of well under one percent here.
    EXPECT_NEAR(tintAt(z), expected, 0.03);
  }

  // Striped volume: monotonic, no jumps.
  rig.volume->setCube(striped);
  double previous = -1.0;
  double largestJump = 0.0;
  for (int i = 0; i <= 25; ++i) {
    const float z = 0.5f - 0.1f * i; // sphere moving away from the eye
    const double tint = tintAt(z);
    if (previous >= 0.0) {
      EXPECT_GE(tint, previous - 0.01) << "tint fell at z = " << z;
      largestJump = std::max(largestJump, tint - previous);
    }
    previous = tint;
  }
  // Measured about 0.022 per move. 0.1 more volume is about 1.2 steps of at
  // most 0.03 alpha each, so 0.06 leaves room while the old behavior, which
  // jumped by 0.1 to 0.2, fails.
  EXPECT_LT(largestJump, 0.06);
  EXPECT_GT(previous, 0.3);
}

TEST_F(GLWidgetTest, volumeGeometryRendersWithoutDepthBuffer)
{
  widget->makeCurrent();
  ContextGuard guard(widget);
  drainGLErrors();

  GLRenderer renderer;
  renderer.initialize();
  ASSERT_TRUE(renderer.isValid()) << renderer.error();
  auto& pipeline = renderer.solidPipeline();
  pipeline.setFogEnabled(false);
  pipeline.setAoEnabled(false);
  pipeline.setEdEnabled(false);
  pipeline.setDofEnabled(false);

  const Cube cube =
    makeUniformCube(Vector3(-3, -3, -3), Vector3(3, 3, 3), 8, 0.4f);
  auto* geometry = new GeometryNode;
  auto* volume = new VolumeGeometry;
  volume->setCube(cube);
  volume->setPositiveColor(Vector3ub(255, 0, 0));
  volume->setRenderPass(TranslucentPass);
  geometry->addDrawable(volume);
  renderer.scene().rootNode().addChild(geometry);
  renderer.scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
  renderer.resetGeometry();
  renderer.resize(96, 96);
  renderer.camera().setIdentity();
  renderer.camera().translate(Vector3f(0.0f, 0.0f, -12.0f));

  // First an FBO with a depth buffer and an opaque sphere hiding the center:
  // the volume snapshots that depth. Then the sphere goes away and the same
  // renderer draws into a color-only FBO, with no depth or stencil
  // attachment. There is nothing to copy, so the volume must draw unoccluded
  // instead of reusing the earlier snapshot (or reading an uninitialized
  // depth texture).
  auto* sphereNode = new GeometryNode;
  auto* spheres = new SphereGeometry;
  sphereNode->addDrawable(spheres);
  // In front of the cube, which ends at z = 3.
  spheres->addSphere(Vector3f(0, 0, 4), Vector3ub(0, 220, 0), 1.5f);
  renderer.scene().rootNode().addChild(sphereNode);
  renderer.resetGeometry();

  QOpenGLFramebufferObject depthFbo(96, 96, QOpenGLFramebufferObject::Depth);
  ASSERT_TRUE(depthFbo.isValid());
  ASSERT_TRUE(depthFbo.bind());
  renderer.resize(96, 96);
  drainGLErrors();
  renderer.render();
  QImage image = depthFbo.toImage();
  ASSERT_FALSE(image.isNull());
  EXPECT_GT(qGreen(image.pixel(48, 48)), 100); // sphere hides the volume
  EXPECT_LT(qRed(image.pixel(48, 48)), 100);
  depthFbo.release();

  spheres->clear();
  renderer.scene().setDirty(true);

  QOpenGLFramebufferObject fbo(96, 96, QOpenGLFramebufferObject::NoAttachment);
  ASSERT_TRUE(fbo.isValid());
  ASSERT_TRUE(fbo.bind());
  renderer.resize(96, 96);
  drainGLErrors();
  // Render twice: the second frame reuses whatever the first set up.
  for (int frame = 0; frame < 2; ++frame) {
    renderer.render();
    image = fbo.toImage();
    EXPECT_EQ(widget->context()->functions()->glGetError(),
              static_cast<GLenum>(GL_NO_ERROR))
      << "frame " << frame;
    ASSERT_FALSE(image.isNull());
    EXPECT_TRUE(isRedVolume(image.pixel(48, 48))) << "frame " << frame;
    EXPECT_TRUE(isBackground(image.pixel(1, 1)));
  }
  fbo.release();
  renderer.cleanup();
}

TEST_F(GLWidgetTest, volumeGeometryAlphaScaleControlsOpacity)
{
  const Cube cube =
    makeUniformCube(Vector3(-3, -3, -3), Vector3(3, 3, 3), 8, 0.5f);
  VolumeRig rig(*widget, &cube);

  // Negative values clamp to zero and NaN is ignored.
  rig.volume->setAlphaScale(-3.0f);
  EXPECT_EQ(rig.volume->alphaScale(), 0.0f);
  rig.volume->setAlphaScale(std::nanf(""));
  EXPECT_EQ(rig.volume->alphaScale(), 0.0f);
  QImage image = rig.render();
  ASSERT_FALSE(image.isNull());
  EXPECT_TRUE(isBackground(rig.pixelAt(image, Vector3f(0, 0, 0))));

  // Unsaturated scales: 0.4 * 0.5 * s per step over about 87 steps, so the
  // center opacity runs from about 0.2 to 0.9. Each doubling must add well
  // over the rounding of an 8-bit channel.
  int previous = 0;
  for (const float scale : { 0.003f, 0.006f, 0.012f, 0.024f }) {
    SCOPED_TRACE(scale);
    rig.volume->setAlphaScale(scale);
    image = rig.render();
    ASSERT_FALSE(image.isNull());
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    const int red = qRed(rig.pixelAt(image, Vector3f(0, 0, 0)));
    EXPECT_GT(red, previous + 20);
    previous = red;
  }
}

TEST_F(GLWidgetTest, volumeGeometryFollowsSkewedCubeGrid)
{
  // Axis vectors (5, 0, 0), (4, 4, 0), (0, 0, 4) from (-4.5, -2, -2): in the
  // z = 0 plane a parallelogram whose x extent at height y is
  // [y - 2.5, y + 2.5], inside the box x in [-4.5, 4.5], y in [-2, 2].
  Avogadro::Matrix3 steps;
  steps << 0.5, 0.4, 0.0, //
    0.0, 0.4, 0.0,        //
    0.0, 0.0, 0.4;
  Cube cube;
  ASSERT_TRUE(
    cube.setStepLimits(Vector3(-4.5, -2.0, -2.0), Vector3i(11, 11, 11), steps));
  ASSERT_FALSE(cube.isAxisAligned());
  std::vector<float> data(cube.data()->size(), 0.5f);
  ASSERT_TRUE(cube.setData(data));

  VolumeRig rig(*widget, &cube);
  const QImage image = rig.render();
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));

  // Inside the parallelogram, more than a unit from any edge.
  for (const Vector3f p : { Vector3f(0, 0, 0), Vector3f(-3.0f, -1.5f, 0),
                            Vector3f(3.0f, 1.5f, 0) })
    EXPECT_TRUE(isRedVolume(rig.pixelAt(image, p))) << p.x() << "," << p.y();
  // Inside the bounding box of the grid, but outside the grid itself.
  for (const Vector3f p :
       { Vector3f(-3.5f, 1.5f, 0), Vector3f(3.5f, -1.5f, 0) })
    EXPECT_TRUE(isBackground(rig.pixelAt(image, p))) << p.x() << "," << p.y();
}

TEST_F(GLWidgetTest, volumeGeometryRendersWithEyeInsideVolume)
{
  // The eye is at z = 1 inside a cube spanning [-3, 3]^3, and the near plane
  // (2 units ahead, at z = -1) is inside too: the ray has to start at the near
  // plane, not at the box entry behind the eye.
  const Cube cube =
    makeUniformCube(Vector3(-3, -3, -3), Vector3(3, 3, 3), 8, 0.4f);
  VolumeRig rig(*widget, &cube);
  rig.volume->setAlphaScale(0.02f);

  for (const auto proj : { Perspective, Orthographic }) {
    SCOPED_TRACE(proj == Perspective ? "perspective" : "orthographic");
    rig.setView(proj, 1.0f);
    const QImage image = rig.render();
    ASSERT_FALSE(image.isNull());
    EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
    const QRgb center = image.pixel(image.width() / 2, image.height() / 2);
    EXPECT_TRUE(isRedVolume(center)) << qRed(center);
    // Visible, but short of saturated: only the part from the near plane to
    // the far plane (z = -1 to z = -5) is sampled.
    EXPECT_GT(qRed(center), 40);
    EXPECT_LT(qRed(center), 240);
  }
}

TEST_F(GLWidgetTest, volumeGeometryColorsFollowDensitySign)
{
  // Positive density is drawn in the positive color, negative in the
  // negative color. Here x < 0 is positive and x > 0 negative.
  Cube cube;
  constexpr int n = 8;
  cube.setLimits(Vector3(-3, -3, -3), Vector3(3, 3, 3), Vector3i(n, n, n));
  for (unsigned int i = 0; i < cube.data()->size(); ++i)
    cube.setValue(i, cube.position(i).x() < 0.0 ? 0.4f : -0.4f);

  VolumeRig rig(*widget, &cube);
  QImage image = rig.render();
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(rig.glError, static_cast<GLenum>(GL_NO_ERROR));
  EXPECT_TRUE(isRedVolume(rig.pixelAt(image, Vector3f(-1.5f, 0, 0))));
  EXPECT_TRUE(isBlueVolume(rig.pixelAt(image, Vector3f(1.5f, 0, 0))));

  // The colors are the ones set, not a fixed pair.
  rig.volume->setPositiveColor(Vector3ub(0, 255, 0));
  rig.volume->setNegativeColor(Vector3ub(255, 255, 0));
  image = rig.render();
  ASSERT_FALSE(image.isNull());
  const QRgb pos = rig.pixelAt(image, Vector3f(-1.5f, 0, 0));
  const QRgb neg = rig.pixelAt(image, Vector3f(1.5f, 0, 0));
  EXPECT_GT(qGreen(pos), 40);
  EXPECT_LT(qRed(pos), 20);
  EXPECT_GT(qRed(neg), 40);
  EXPECT_GT(qGreen(neg), 40);
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
