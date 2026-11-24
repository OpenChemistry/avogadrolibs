/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtGui/QImage>

#include <string>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereGeometry;
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
