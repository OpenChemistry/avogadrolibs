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
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <QtCore/QRect>
#include <QtGui/QImage>

#include <cmath>
#include <functional>
#include <string>

using Avogadro::Vector2i;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;
using namespace Avogadro::TestGL;

namespace {

// A dark background keeps the antialiased edges of the colored text from
// looking like another color.
const Vector4ub Background(10, 10, 10, 255);

class QtTextLabelTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    std::string reason;
    widget = sharedWidget(reason);
    if (widget == nullptr)
      GTEST_SKIP() << reason;
  }

  // Build a fresh scene (a small gray reference sphere at the origin, plus
  // whatever the callback adds) and grab the result. The callback runs with the
  // widget's context current, as the label constructors require.
  QImage renderScene(
    const std::function<void(GeometryNode*, SphereGeometry*)>& populate,
    const char* name)
  {
    clearScene(*widget);
    widget->makeCurrent();
    auto* geometry = new GeometryNode;
    auto* spheres = new SphereGeometry;
    geometry->addDrawable(spheres);
    spheres->addSphere(Vector3f::Zero(), Vector3ub(128, 128, 128), 0.1f);
    widget->renderer().scene().rootNode().addChild(geometry);
    populate(geometry, spheres);
    widget->renderer().scene().setBackgroundColor(Background);
    widget->renderer().solidPipeline().setBackgroundColor(Background);
    widget->renderer().resetGeometry();
    widget->renderer().resetCamera();
    widget->doneCurrent();
    settle();

    QImage image = widget->grabFramebuffer();
    saveForInspection(image, QString("qttextlabel-%1.png").arg(name));
    return image;
  }

  // The widget's size in the units of the 2D label anchors.
  int widgetWidth() const { return widget->width(); }
  int widgetHeight() const { return widget->height(); }

  GLWidget* widget = nullptr;
};

TextProperties redText(TextProperties::HAlign h, TextProperties::VAlign v)
{
  TextProperties tprop;
  tprop.setColorRgb(255, 0, 0);
  tprop.setAlign(h, v);
  return tprop;
}

Bounds redBounds(const QImage& image)
{
  return dominantBounds(image, 0, 150, 70);
}

} // namespace

TEST_F(QtTextLabelTest, label2DUpperLeftCorner)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel2D;
      label->setText("Upper Left Corner");
      label->setAnchor(Vector2i(0, widgetHeight()));
      label->setTextProperties(
        redText(TextProperties::HLeft, TextProperties::VTop));
      geometry->addDrawable(label);
    },
    "2d-upper-left");
  ASSERT_FALSE(image.isNull());
  const Bounds b = redBounds(image);
  ASSERT_GT(b.count, 20);
  EXPECT_LT(b.minX, 0.05 * image.width());
  EXPECT_LT(b.minY, 0.05 * image.height());
  EXPECT_LT(b.maxX, 0.75 * image.width());
  EXPECT_LT(b.maxY, 0.25 * image.height());
}

TEST_F(QtTextLabelTest, label2DBottomLeftCorner)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel2D;
      label->setText("Bottom Left Corner");
      label->setAnchor(Vector2i(0, 0));
      label->setTextProperties(
        redText(TextProperties::HLeft, TextProperties::VBottom));
      geometry->addDrawable(label);
    },
    "2d-bottom-left");
  ASSERT_FALSE(image.isNull());
  const Bounds b = redBounds(image);
  ASSERT_GT(b.count, 20);
  EXPECT_LT(b.minX, 0.05 * image.width());
  EXPECT_GT(b.maxY, 0.95 * image.height());
  EXPECT_GT(b.minY, 0.75 * image.height());
}

TEST_F(QtTextLabelTest, label2DUpperRightCorner)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel2D;
      label->setText("Upper Right Corner");
      label->setAnchor(Vector2i(widgetWidth(), widgetHeight()));
      label->setTextProperties(
        redText(TextProperties::HRight, TextProperties::VTop));
      geometry->addDrawable(label);
    },
    "2d-upper-right");
  ASSERT_FALSE(image.isNull());
  const Bounds b = redBounds(image);
  ASSERT_GT(b.count, 20);
  EXPECT_GT(b.maxX, 0.95 * image.width());
  EXPECT_LT(b.minY, 0.05 * image.height());
  EXPECT_GT(b.minX, 0.25 * image.width());
}

TEST_F(QtTextLabelTest, label2DBottomRightCorner)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel2D;
      label->setText("Bottom Right Corner");
      label->setAnchor(Vector2i(widgetWidth(), 0));
      label->setTextProperties(
        redText(TextProperties::HRight, TextProperties::VBottom));
      geometry->addDrawable(label);
    },
    "2d-bottom-right");
  ASSERT_FALSE(image.isNull());
  const Bounds b = redBounds(image);
  ASSERT_GT(b.count, 20);
  EXPECT_GT(b.maxX, 0.95 * image.width());
  EXPECT_GT(b.maxY, 0.95 * image.height());
}

TEST_F(QtTextLabelTest, label2DCentered)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel2D;
      label->setText("Centered Anchor (2D)");
      label->setAnchor(Vector2i(widgetWidth() / 2, widgetHeight() / 2));
      TextProperties tprop =
        redText(TextProperties::HCenter, TextProperties::VCenter);
      tprop.setAlpha(220);
      label->setTextProperties(tprop);
      geometry->addDrawable(label);
    },
    "2d-centered");
  ASSERT_FALSE(image.isNull());
  // Translucent text over a dark background is darker red than the pure color.
  const Bounds b = dominantBounds(image, 0, 100, 60);
  ASSERT_GT(b.count, 20);
  EXPECT_NEAR(b.centerX(), image.width() / 2.0, 0.03 * image.width());
  EXPECT_NEAR(b.centerY(), image.height() / 2.0, 0.05 * image.height());
  EXPECT_GT(b.maxX - b.minX, b.maxY - b.minY);
}

TEST_F(QtTextLabelTest, label3DAlignmentAroundAnchor)
{
  struct Case
  {
    TextProperties::HAlign h;
    TextProperties::VAlign v;
    const char* name;
  };
  const Case cases[] = {
    { TextProperties::HLeft, TextProperties::VTop, "left-top" },
    { TextProperties::HLeft, TextProperties::VBottom, "left-bottom" },
    { TextProperties::HRight, TextProperties::VTop, "right-top" },
    { TextProperties::HRight, TextProperties::VBottom, "right-bottom" },
  };

  for (const Case& c : cases) {
    SCOPED_TRACE(c.name);
    const QImage image = renderScene(
      [&](GeometryNode* geometry, SphereGeometry*) {
        auto* label = new TextLabel3D;
        label->setText("Anchor");
        label->setAnchor(Vector3f::Zero());
        label->setTextProperties(redText(c.h, c.v));
        geometry->addDrawable(label);
      },
      c.name);
    ASSERT_FALSE(image.isNull());
    const Bounds b = redBounds(image);
    ASSERT_GT(b.count, 20);

    const QPointF anchor = screenPoint(*widget, image, Vector3f::Zero());
    // A few pixels of slack for antialiasing and rounding of the anchor.
    const double slack = 3.0 * widget->devicePixelRatioF();
    if (c.h == TextProperties::HLeft)
      EXPECT_GE(b.minX, anchor.x() - slack); // text extends to the right
    else
      EXPECT_LE(b.maxX + 1, anchor.x() + slack); // ... or to the left
    if (c.v == TextProperties::VTop)
      EXPECT_GE(b.minY, anchor.y() - slack); // text hangs below the anchor
    else
      EXPECT_LE(b.maxY + 1, anchor.y() + slack); // ... or sits above it
  }
}

TEST_F(QtTextLabelTest, label3DCenteredAndRotated)
{
  const QImage image = renderScene(
    [&](GeometryNode* geometry, SphereGeometry*) {
      auto* label = new TextLabel3D;
      label->setText("Centered Anchor (3D)");
      label->setAnchor(Vector3f::Zero());
      TextProperties tprop =
        redText(TextProperties::HCenter, TextProperties::VCenter);
      tprop.setRotationDegreesCW(90.f);
      label->setTextProperties(tprop);
      geometry->addDrawable(label);
    },
    "3d-centered-rotated");
  ASSERT_FALSE(image.isNull());
  const Bounds b = redBounds(image);
  ASSERT_GT(b.count, 20);

  const QPointF anchor = screenPoint(*widget, image, Vector3f::Zero());
  const double slack = 4.0 * widget->devicePixelRatioF();
  EXPECT_NEAR(b.centerX(), anchor.x(), slack);
  EXPECT_NEAR(b.centerY(), anchor.y(), slack);
  // Rotated a quarter turn, the long text runs vertically.
  EXPECT_GT(b.maxY - b.minY, b.maxX - b.minX);
}

TEST_F(QtTextLabelTest, label3DRadiusLiftsLabelOutOfSphere)
{
  const Vector3f center(0.f, 6.f, 0.f);
  auto addScene = [&](bool sphere, float radius) {
    return [&, sphere, radius](GeometryNode* geometry, SphereGeometry* s) {
      if (sphere)
        s->addSphere(center, Vector3ub(255, 255, 255), 1.f);
      auto* label = new TextLabel3D;
      label->setText("Radius");
      label->setAnchor(center);
      TextProperties tprop =
        redText(TextProperties::HCenter, TextProperties::VCenter);
      label->setTextProperties(tprop);
      if (radius > 0.f)
        label->setRadius(radius);
      geometry->addDrawable(label);
    };
  };

  // The label is wider than the sphere, so only count the part of it that
  // overlaps the sphere's disc on screen (a square inside the disc). Each scene
  // frames its own geometry, so measure with the camera right after rendering.
  auto countInside = [&](const QImage& image) {
    const QPointF c = screenPoint(*widget, image, center);
    const QPointF edge =
      screenPoint(*widget, image, center + Vector3f(1.f, 0.f, 0.f));
    const double r = 1.0 * std::abs(edge.x() - c.x());
    const QRect inside(qRound(c.x() - 0.6 * r), qRound(c.y() - 0.6 * r),
                       qRound(1.2 * r), qRound(1.2 * r));
    return redBounds(image.copy(inside)).count;
  };

  // Unobstructed label, for reference.
  const QImage open = renderScene(addScene(false, 0.f), "radius-open");
  ASSERT_FALSE(open.isNull());
  const int openCount = countInside(open);
  // Anchored at a sphere center with no radius: inside the sphere.
  const QImage clipped = renderScene(addScene(true, 0.f), "radius-clipped");
  ASSERT_FALSE(clipped.isNull());
  const int clippedCount = countInside(clipped);
  // The same label, offset toward the camera by the sphere's radius.
  const QImage projected = renderScene(addScene(true, 1.f), "radius-projected");
  ASSERT_FALSE(projected.isNull());
  const int projectedCount = countInside(projected);

  ASSERT_GT(openCount, 20);
  // The sphere hides the label where they overlap when there is no radius...
  EXPECT_LT(clippedCount, 0.1 * openCount);
  // ... and the radius brings that part of it back.
  EXPECT_GT(projectedCount, 0.7 * openCount);
}
