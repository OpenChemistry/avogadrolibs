/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/bsplinegeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/shader.h>
#include <avogadro/rendering/shaderprogram.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/texture2d.h>

#include <QtGui/QImage>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLFunctions>

#include <string>
#include <vector>

using Avogadro::Vector2i;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::Rendering::ArrowGeometry;
using Avogadro::Rendering::BSplineGeometry;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::Shader;
using Avogadro::Rendering::ShaderProgram;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::Rendering::Texture2D;
using Avogadro::Rendering::TranslucentPass;
using namespace Avogadro::TestGL;

namespace {

const Vector4ub Background(40, 80, 120, 255);

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

  GLWidget* widget = nullptr;
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

TEST_F(GLWidgetTest, hiddenDrawableIsNotRendered)
{
  clearScene(*widget);
  widget->makeCurrent();
  auto* geometry = new GeometryNode;
  auto* visibleSphere = new SphereGeometry;
  visibleSphere->addSphere(Vector3f(-1.5f, 0, 0), Vector3ub(255, 0, 0), 1.0f);
  auto* hiddenSphere = new SphereGeometry;
  hiddenSphere->addSphere(Vector3f(1.5f, 0, 0), Vector3ub(0, 255, 0), 1.0f);
  hiddenSphere->setVisible(false);
  geometry->addDrawable(visibleSphere);
  geometry->addDrawable(hiddenSphere);
  widget->renderer().scene().rootNode().addChild(geometry);
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  widget->doneCurrent();
  settle();

  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  const Bounds red = dominantBounds(image, 0, 90, 60);
  const Bounds green = dominantBounds(image, 1, 90, 60);
  EXPECT_GT(red.count, 20);
  EXPECT_EQ(green.count, 0);
}

TEST_F(GLWidgetTest, curveGeometrySetsOpacityForTranslucentPass)
{
  clearScene(*widget);
  widget->makeCurrent();
  auto* geometry = new GeometryNode;
  auto* curve = new BSplineGeometry(false);
  curve->setRenderPass(TranslucentPass);
  curve->addPoint(Vector3f(-2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0,
                  0);
  curve->addPoint(Vector3f(0.0f, 0.5f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 1);
  curve->addPoint(Vector3f(2.0f, 0.0f, 0.0f), Vector3ub(255, 0, 0), 0.5f, 0, 2);
  geometry->addDrawable(curve);
  widget->renderer().scene().rootNode().addChild(geometry);
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  widget->doneCurrent();
  settle();

  const QImage image = widget->grabFramebuffer();
  ASSERT_FALSE(image.isNull());
  // Without CurveGeometry::render() setting opacity = 1.0, alpha defaults to
  // 0.0 and TranslucentPass blending makes the curve completely invisible.
  const Bounds red = dominantBounds(image, 0, 90, 60);
  EXPECT_GT(red.count, 50);
}

TEST_F(GLWidgetTest, arrowGeometryLitFromUpperFront)
{
  clearScene(*widget);
  widget->makeCurrent();
  auto* geometry = new GeometryNode;
  auto* arrow = new ArrowGeometry;
  arrow->setRadiusScale(4.0f);
  arrow->addSingleArrow(Vector3f(-2.5f, 0.0f, 0.0f), Vector3f(2.5f, 0.0f, 0.0f),
                        Vector3ub(220, 220, 220));
  geometry->addDrawable(arrow);
  widget->renderer().scene().rootNode().addChild(geometry);
  widget->renderer().scene().setBackgroundColor(Vector4ub(0, 0, 0, 255));
  widget->renderer().solidPipeline().setBackgroundColor(
    Vector4ub(0, 0, 0, 255));
  widget->renderer().resetGeometry();
  widget->renderer().resetCamera();
  widget->doneCurrent();
  settle();

  const QImage image = widget->grabFramebuffer();
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
  // Declared before any GL object so it is destroyed last: the shaders,
  // program and texture are deleted while the context is still current,
  // on both the success and the early-return paths.
  struct ContextGuard
  {
    GLWidget* widget;
    ~ContextGuard()
    {
      if (QOpenGLContext* ctx = QOpenGLContext::currentContext())
        ctx->functions()->glUseProgram(0);
      widget->doneCurrent();
    }
  } guard{ widget };
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
