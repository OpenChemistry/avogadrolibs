/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// GL tests of the solid pipeline's linear fog, depth of field and ambient
// occlusion. They need a GL context and skip without one.

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/qtopengl/renderoptions.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/solidpipeline.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtGui/QImage>
#include <QtGui/QOpenGLContext>
#include <QtGui/QOpenGLFunctions>

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::QtOpenGL::RenderOptions;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::Orthographic;
using Avogadro::Rendering::Perspective;
using Avogadro::Rendering::SolidPipeline;
using Avogadro::Rendering::SphereGeometry;
using namespace Avogadro::TestGL;

namespace {

// Saves every pipeline setting the tests change and restores it on exit, along
// with the camera projection and the scene.
struct PipelineSettingsGuard
{
  explicit PipelineSettingsGuard(GLWidget* glWidget)
    : widget(glWidget), p(glWidget->renderer().solidPipeline()),
      fog(p.getFogEnabled()), ao(p.getAoEnabled()), ed(p.getEdEnabled()),
      dof(p.getDofEnabled()), aoStrength(p.getAoStrength()),
      fogStrength(p.getFogStrength()), fogPosition(p.getFogPosition()),
      dofStrength(p.getDofStrength()), dofPosition(p.getDofPosition()),
      projection(glWidget->renderer().camera().projectionType())
  {
  }
  ~PipelineSettingsGuard()
  {
    clearScene(*widget);
    p.setFogEnabled(fog);
    p.setAoEnabled(ao);
    p.setAoStrength(aoStrength);
    p.setEdEnabled(ed);
    p.setDofEnabled(dof);
    p.setFogStrength(fogStrength);
    p.setFogPosition(fogPosition);
    p.setDofStrength(dofStrength);
    p.setDofPosition(dofPosition);
    widget->renderer().camera().setProjectionType(projection);
  }
  GLWidget* widget;
  SolidPipeline& p;
  bool fog, ao, ed, dof;
  float aoStrength, fogStrength, fogPosition, dofStrength, dofPosition;
  Avogadro::Rendering::Projection projection;
};

class SolidEffectsTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    std::string reason;
    widget = sharedWidget(reason);
    if (widget == nullptr)
      GTEST_SKIP() << reason;
    guard = std::make_unique<PipelineSettingsGuard>(widget);
    SolidPipeline& p = widget->renderer().solidPipeline();
    p.setAoEnabled(false);
    p.setEdEnabled(false);
    p.setFogEnabled(false);
    p.setDofEnabled(false);
  }
  void TearDown() override { guard.reset(); }

  SolidPipeline& pipeline() { return widget->renderer().solidPipeline(); }

  // Replace the scene with the node, view it from a fixed camera along +Z
  // with the given projection, and return the frame. Checks for GL errors.
  QImage render(GeometryNode* node, Avogadro::Rendering::Projection projection,
                const Vector4ub& background)
  {
    clearScene(*widget);
    widget->makeCurrent();
    drainGLErrors();
    widget->renderer().scene().rootNode().addChild(node);
    widget->renderer().scene().setBackgroundColor(background);
    pipeline().setBackgroundColor(background);
    widget->renderer().camera().setProjectionType(projection);
    widget->renderer().resetGeometry();
    widget->renderer().camera().setIdentity();
    widget->renderer().camera().translate(Vector3f(0.0f, 0.0f, -12.0f));
    widget->doneCurrent();
    settle();
    QImage image = widget->grabFramebuffer();
    widget->makeCurrent();
    EXPECT_EQ(widget->context()->functions()->glGetError(),
              static_cast<GLenum>(GL_NO_ERROR));
    widget->doneCurrent();
    return image;
  }

  // Two spheres of one color, the left one nearer the camera.
  QImage twoSpheres(const Vector3ub& color,
                    Avogadro::Rendering::Projection projection,
                    const Vector4ub& background)
  {
    auto* node = new GeometryNode;
    auto* spheres = new SphereGeometry;
    node->addDrawable(spheres);
    spheres->addSphere(Vector3f(-1.5f, 0.0f, 2.0f), color, 0.8f);
    spheres->addSphere(Vector3f(1.5f, 0.0f, -2.0f), color, 0.8f);
    return render(node, projection, background);
  }

  QRgb pixelAt(const QImage& image, const Vector3f& scenePoint)
  {
    const QPointF p = screenPoint(*widget, image, scenePoint);
    return image.pixel(qBound(0, qRound(p.x()), image.width() - 1),
                       qBound(0, qRound(p.y()), image.height() - 1));
  }

  // A 4 x 4 slab of overlapping red and blue spheres in a checkerboard, so
  // that blur shows as lost contrast between neighbors. One slab at x = -3 and
  // one at x = +3, at the two depths.
  static void addSlab(SphereGeometry* spheres, float centerX, float z)
  {
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        const Vector3ub color =
          ((i + j) % 2 == 0) ? Vector3ub(255, 0, 0) : Vector3ub(0, 0, 255);
        spheres->addSphere(
          Vector3f(centerX + (i - 1.5f) * 0.8f, (j - 1.5f) * 0.8f, z), color,
          0.5f);
      }
    }
  }

  QImage slabs(const Vector4ub& background)
  {
    auto* node = new GeometryNode;
    auto* spheres = new SphereGeometry;
    node->addDrawable(spheres);
    addSlab(spheres, -3.0f, 4.0f); // Near the camera.
    addSlab(spheres, 3.0f, -4.0f); // Far from it.
    return render(node, Orthographic, background);
  }

  // Mean absolute horizontal difference of red minus blue over a window of
  // +-1 scene unit around the slab center: high for a sharp checkerboard.
  double slabContrast(const QImage& image, float centerX)
  {
    const QPointF c = screenPoint(*widget, image, Vector3f(centerX, 0, 0));
    const QPointF e = screenPoint(*widget, image, Vector3f(centerX + 1, 0, 0));
    const int half = std::max(4, qRound(std::abs(e.x() - c.x())));
    double sum = 0.0;
    int count = 0;
    for (int y = qRound(c.y()) - half; y <= qRound(c.y()) + half; ++y) {
      for (int x = qRound(c.x()) - half; x < qRound(c.x()) + half; ++x) {
        const QRgb a = image.pixel(x, y);
        const QRgb b = image.pixel(x + 1, y);
        sum += std::abs((qRed(a) - qBlue(a)) - (qRed(b) - qBlue(b)));
        ++count;
      }
    }
    return sum / std::max(1, count);
  }

  // The depth of field position that focuses on the slab plane at x = -3
  // (near) or x = +3 (far), which lie 4 units either side of the scene center.
  // Mapping: 0..1 runs from the front of the bounding sphere to its center, and
  // 1..20 from the center to the back.
  float focusPosition(bool nearSlab)
  {
    const float radius = widget->renderer().scene().radius();
    const float f = 4.0f / std::max(radius, 1e-3f);
    return nearSlab ? 1.0f - f : 1.0f + 19.0f * f;
  }

  double slabMeanGreen(const QImage& image, float centerX)
  {
    const QPointF c = screenPoint(*widget, image, Vector3f(centerX, 0, 0));
    double sum = 0.0;
    int count = 0;
    for (int y = qRound(c.y()) - 10; y <= qRound(c.y()) + 10; ++y) {
      for (int x = qRound(c.x()) - 10; x <= qRound(c.x()) + 10; ++x) {
        sum += qGreen(image.pixel(x, y));
        ++count;
      }
    }
    return sum / count;
  }

  GLWidget* widget = nullptr;
  std::unique_ptr<PipelineSettingsGuard> guard;
};

const Vector4ub White(255, 255, 255, 255);
const Vector4ub Black(0, 0, 0, 255);

} // namespace

TEST_F(SolidEffectsTest, nearerSphereIsLessFogged)
{
  for (const auto projection : { Perspective, Orthographic }) {
    SCOPED_TRACE(projection == Perspective ? "perspective" : "orthographic");
    pipeline().setFogEnabled(false);
    const QImage plain = twoSpheres(Vector3ub(200, 0, 0), projection, White);
    ASSERT_FALSE(plain.isNull());
    // Without fog the two spheres are the same red, within shading.
    const int plainFront = qGreen(pixelAt(plain, Vector3f(-1.5f, 0, 2.8f)));
    const int plainBack = qGreen(pixelAt(plain, Vector3f(1.5f, 0, -1.2f)));
    EXPECT_LT(std::abs(plainFront - plainBack), 10);

    pipeline().setFogEnabled(true);
    pipeline().setFogStrength(6.0f);
    pipeline().setFogPosition(-5.0f);
    const QImage fogged = twoSpheres(Vector3ub(200, 0, 0), projection, White);
    ASSERT_FALSE(fogged.isNull());
    const int front = qGreen(pixelAt(fogged, Vector3f(-1.5f, 0, 2.8f)));
    const int back = qGreen(pixelAt(fogged, Vector3f(1.5f, 0, -1.2f)));
    // Fog on a white background adds white: the farther one has more.
    EXPECT_GT(back, front + 25);
    EXPECT_GE(front, plainFront);
  }
}

TEST_F(SolidEffectsTest, fogDoesNotLiftBlackOnBlack)
{
  for (const auto projection : { Perspective, Orthographic }) {
    SCOPED_TRACE(projection == Perspective ? "perspective" : "orthographic");
    pipeline().setFogEnabled(false);
    const QImage plain = twoSpheres(Vector3ub(0, 0, 0), projection, Black);
    pipeline().setFogEnabled(true);
    pipeline().setFogStrength(20.0f);
    pipeline().setFogPosition(-20.0f);
    const QImage fogged = twoSpheres(Vector3ub(0, 0, 0), projection, Black);
    ASSERT_FALSE(plain.isNull());
    ASSERT_EQ(plain.size(), fogged.size());
    // Fog mixes toward black, so no pixel can get brighter, and the spheres'
    // black must stay black.
    int worst = -255;
    for (int y = 0; y < plain.height(); ++y) {
      for (int x = 0; x < plain.width(); ++x) {
        const QRgb a = plain.pixel(x, y);
        const QRgb b = fogged.pixel(x, y);
        worst = std::max({ worst, qRed(b) - qRed(a), qGreen(b) - qGreen(a),
                           qBlue(b) - qBlue(a) });
      }
    }
    EXPECT_LE(worst, 1);
    // The black material still has its shading, which fog can only reduce.
    const QRgb before = pixelAt(plain, Vector3f(1.5f, 0.0f, -1.5f));
    const QRgb after = pixelAt(fogged, Vector3f(1.5f, 0.0f, -1.5f));
    EXPECT_LE(qRed(after) + qGreen(after) + qBlue(after),
              qRed(before) + qGreen(before) + qBlue(before));
  }
}

TEST_F(SolidEffectsTest, blackFadesTowardWhiteWithDepth)
{
  for (const auto projection : { Perspective, Orthographic }) {
    SCOPED_TRACE(projection == Perspective ? "perspective" : "orthographic");
    pipeline().setFogEnabled(true);
    pipeline().setFogStrength(6.0f);
    pipeline().setFogPosition(-5.0f);
    const QImage image = twoSpheres(Vector3ub(0, 0, 0), projection, White);
    ASSERT_FALSE(image.isNull());
    const int front = qGreen(pixelAt(image, Vector3f(-1.5f, 0, 2.2f)));
    const int back = qGreen(pixelAt(image, Vector3f(1.5f, 0, -1.8f)));
    EXPECT_GT(back, front + 25);
    EXPECT_GT(back, 60);
  }
}

TEST_F(SolidEffectsTest, depthOfFieldBlursAwayFromTheFocus)
{
  pipeline().setDofEnabled(true);
  pipeline().setDofStrength(2.0f);

  // Focus on the near slab: it stays sharp.
  QImage image = slabs(White);
  ASSERT_FALSE(image.isNull());
  pipeline().setDofPosition(focusPosition(true));
  image = slabs(White);
  const double nearSharp = slabContrast(image, -3.0f);
  const double farBlurred = slabContrast(image, 3.0f);
  EXPECT_GT(nearSharp, 1.3 * farBlurred);

  // Focus on the back: the other way around.
  pipeline().setDofPosition(focusPosition(false));
  image = slabs(White);
  ASSERT_FALSE(image.isNull());
  EXPECT_GT(slabContrast(image, 3.0f), 1.3 * slabContrast(image, -3.0f));

  // Off, both are as sharp as the in-focus slabs were.
  pipeline().setDofEnabled(false);
  image = slabs(White);
  EXPECT_GT(slabContrast(image, -3.0f), 0.9 * nearSharp);
  EXPECT_GT(slabContrast(image, 3.0f), 0.9 * nearSharp);
}

TEST_F(SolidEffectsTest, fogAndDepthOfFieldCombineWithoutWashout)
{
  pipeline().setDofStrength(2.0f);
  pipeline().setFogStrength(6.0f);
  pipeline().setFogPosition(1.0f);

  const QImage plain = slabs(White);
  pipeline().setDofPosition(focusPosition(true));
  pipeline().setDofEnabled(true);
  const QImage dofOnly = slabs(White);
  pipeline().setDofEnabled(false);
  pipeline().setFogEnabled(true);
  const QImage fogOnly = slabs(White);
  pipeline().setDofEnabled(true);
  const QImage both = slabs(White);
  ASSERT_FALSE(both.isNull());

  // The near slab is in focus and in front of the fog, so fog adds nothing to
  // the blur's result: it is not mixed halfway with anything.
  const Vector3f nearPoint(-3.0f + 0.4f, 0.4f, 4.5f);
  const QRgb a = pixelAt(dofOnly, nearPoint);
  const QRgb b = pixelAt(both, nearPoint);
  EXPECT_NEAR(qRed(a), qRed(b), 3);
  EXPECT_NEAR(qGreen(a), qGreen(b), 3);
  EXPECT_NEAR(qBlue(a), qBlue(b), 3);

  // The far slab is both: fogged (lighter than blur alone) and blurred (less
  // contrast than fog alone).
  EXPECT_GT(slabMeanGreen(both, 3.0f), slabMeanGreen(dofOnly, 3.0f) + 15);
  EXPECT_LT(slabContrast(both, 3.0f), 0.8 * slabContrast(fogOnly, 3.0f));
  // And each effect alone does its own thing.
  EXPECT_GT(slabMeanGreen(fogOnly, 3.0f), slabMeanGreen(plain, 3.0f) + 15);
  EXPECT_LT(slabContrast(dofOnly, 3.0f), 0.8 * slabContrast(plain, 3.0f));
}

TEST_F(SolidEffectsTest, transparentBackgroundFadesToTransparent)
{
  pipeline().setFogEnabled(true);
  pipeline().setFogStrength(20.0f);
  pipeline().setFogPosition(-20.0f);
  // The window's framebuffer has no alpha, so render offscreen. The scene and
  // camera are set up by showing the spheres first.
  ASSERT_FALSE(
    twoSpheres(Vector3ub(200, 0, 0), Orthographic, Vector4ub(0, 0, 0, 0))
      .isNull());
  RenderOptions options;
  options.size = QSize(400, 300);
  options.transparentBackground = true;
  const QImage image =
    widget->renderImage(options).convertToFormat(QImage::Format_ARGB32);
  ASSERT_FALSE(image.isNull());
  const int frontAlpha = qAlpha(pixelAt(image, Vector3f(-1.5f, 0, 2.8f)));
  const int backAlpha = qAlpha(pixelAt(image, Vector3f(1.5f, 0, -1.2f)));
  EXPECT_GT(frontAlpha, backAlpha + 30);
}

namespace {

double luminance(QRgb pixel)
{
  return 0.299 * qRed(pixel) + 0.587 * qGreen(pixel) + 0.114 * qBlue(pixel);
}

// Mean luminance over a (2 * half + 1) pixel square around a scene point.
double meanLuminance(GLWidget* widget, const QImage& image,
                     const Vector3f& scenePoint, int half)
{
  const QPointF p = screenPoint(*widget, image, scenePoint);
  double sum = 0.0;
  int count = 0;
  for (int y = qRound(p.y()) - half; y <= qRound(p.y()) + half; ++y) {
    for (int x = qRound(p.x()) - half; x <= qRound(p.x()) + half; ++x) {
      if (x < 0 || y < 0 || x >= image.width() || y >= image.height())
        continue;
      sum += luminance(image.pixel(x, y));
      ++count;
    }
  }
  return count > 0 ? sum / count : 0.0;
}

// Restores the widget to the size the other suites expect.
struct WidgetSizeGuard
{
  explicit WidgetSizeGuard(GLWidget* glWidget)
    : widget(glWidget), size(glWidget->size())
  {
  }
  ~WidgetSizeGuard()
  {
    widget->resize(size);
    settle();
  }
  GLWidget* widget;
  QSize size;
};

} // namespace

// Two spheres of one color touching at x = 0; the crevice is the pair of
// surface patches either side of the contact point.
class SolidAoTest : public SolidEffectsTest
{
protected:
  QImage touchingSpheres(const Vector4ub& background,
                         Avogadro::Rendering::Projection projection)
  {
    auto* node = new GeometryNode;
    auto* spheres = new SphereGeometry;
    node->addDrawable(spheres);
    spheres->addSphere(Vector3f(-2.0f, 0.0f, 0.0f), Vector3ub(200, 0, 0), 2.0f);
    spheres->addSphere(Vector3f(2.0f, 0.0f, 0.0f), Vector3ub(200, 0, 0), 2.0f);
    return render(node, projection, background);
  }

  // A point on the left sphere's near surface, a little off the contact point.
  static Vector3f creviceNearContact() { return Vector3f(-0.3f, 0.0f, 1.05f); }
  // A point on the same sphere's far side from the other one.
  static Vector3f openSurface() { return Vector3f(-3.5f, 0.0f, 1.32f); }

  // How much darker AO makes the crevice, relative to the open surface, as the
  // ratio of the two ratios (AO on over AO off). Below 1: the crevice is
  // darker than the open surface once the shading is divided out.
  double creviceDarkening(Avogadro::Rendering::Projection projection)
  {
    pipeline().setAoStrength(2.0f);
    pipeline().setAoEnabled(false);
    const QImage off = touchingSpheres(White, projection);
    pipeline().setAoEnabled(true);
    const QImage on = touchingSpheres(White, projection);
    EXPECT_FALSE(off.isNull());
    EXPECT_EQ(off.size(), on.size());
    if (off.isNull() || off.size() != on.size())
      return 1.0;
    const double crevice =
      meanLuminance(widget, on, creviceNearContact(), 2) /
      std::max(1.0, meanLuminance(widget, off, creviceNearContact(), 2));
    const double open =
      meanLuminance(widget, on, openSurface(), 2) /
      std::max(1.0, meanLuminance(widget, off, openSurface(), 2));
    return crevice / std::max(open, 1e-3);
  }
};

TEST_F(SolidAoTest, darkensTheCreviceBetweenTouchingSpheres)
{
  for (const auto projection : { Perspective, Orthographic }) {
    SCOPED_TRACE(projection == Perspective ? "perspective" : "orthographic");
    EXPECT_LT(creviceDarkening(projection), 0.85);
  }
}

TEST_F(SolidAoTest, leavesBackgroundPixelsAlone)
{
  for (const Vector4ub background : { White, Black }) {
    SCOPED_TRACE(background[0] == 255 ? "white" : "black");
    pipeline().setAoEnabled(false);
    const QImage off = touchingSpheres(background, Perspective);
    pipeline().setAoEnabled(true);
    const QImage on = touchingSpheres(background, Perspective);
    ASSERT_FALSE(off.isNull());
    ASSERT_EQ(off.size(), on.size());
    const QRgb bg = qRgb(background[0], background[1], background[2]);
    int mismatched = 0;
    int background_pixels = 0;
    for (int y = 0; y < off.height(); ++y) {
      for (int x = 0; x < off.width(); ++x) {
        const bool wasBackground = off.pixel(x, y) == bg;
        const bool isBackground = on.pixel(x, y) == bg;
        mismatched += wasBackground != isBackground ? 1 : 0;
        background_pixels += wasBackground ? 1 : 0;
      }
    }
    EXPECT_GT(background_pixels, off.width() * off.height() / 2);
    // Every pixel that was background still is, and the molecule's pixels did
    // not turn into background.
    EXPECT_EQ(mismatched, 0);
  }
}

TEST_F(SolidAoTest, smoothSurfaceHasNoDitherOrSpikes)
{
  // One large sphere has nothing to be occluded by but itself: its occlusion
  // term is smooth, so what is left of a high-pass filter is the sampling
  // pattern of the kernel and any outliers.
  for (const auto projection : { Perspective, Orthographic }) {
    SCOPED_TRACE(projection == Perspective ? "perspective" : "orthographic");
    auto* node = new GeometryNode;
    auto* spheres = new SphereGeometry;
    node->addDrawable(spheres);
    spheres->addSphere(Vector3f(0.0f, 0.0f, 0.0f), Vector3ub(200, 200, 200),
                       4.0f);
    pipeline().setAoEnabled(false);
    const QImage off = render(node, projection, White);
    pipeline().setAoEnabled(true);
    node = new GeometryNode;
    spheres = new SphereGeometry;
    node->addDrawable(spheres);
    spheres->addSphere(Vector3f(0.0f, 0.0f, 0.0f), Vector3ub(200, 200, 200),
                       4.0f);
    const QImage on = render(node, projection, White);
    ASSERT_FALSE(on.isNull());
    ASSERT_EQ(off.size(), on.size());

    // A window around the sphere's center, well inside its silhouette. The AO
    // term is the ratio of the two renders.
    const QPointF c = screenPoint(*widget, on, Vector3f(0.0f, 0.0f, 4.0f));
    const int half = std::max(8, std::min(on.width(), on.height()) / 12);
    constexpr int blur = 4; // Box radius of the smoothed copy.
    double sumSquares = 0.0;
    double worst = 0.0;
    int count = 0;
    for (int y = qRound(c.y()) - half; y <= qRound(c.y()) + half; ++y) {
      for (int x = qRound(c.x()) - half; x <= qRound(c.x()) + half; ++x) {
        auto term = [&](int px, int py) {
          return luminance(on.pixel(px, py)) /
                 std::max(1.0, luminance(off.pixel(px, py)));
        };
        double mean = 0.0;
        for (int dy = -blur; dy <= blur; ++dy)
          for (int dx = -blur; dx <= blur; ++dx)
            mean += term(x + dx, y + dy);
        mean /= (2 * blur + 1) * (2 * blur + 1);
        const double residual = term(x, y) - mean;
        ASSERT_TRUE(std::isfinite(residual));
        sumSquares += residual * residual;
        worst = std::max(worst, std::abs(residual));
        ++count;
        // Not black, and not blown out: no NaN made it into the term.
        EXPECT_GT(luminance(on.pixel(x, y)), 20.0);
      }
    }
    const double rms = std::sqrt(sumSquares / std::max(1, count));
    EXPECT_LT(rms, 0.01);
    EXPECT_LT(worst, 0.05);
  }
}

TEST_F(SolidAoTest, oddFrameSizesWork)
{
  WidgetSizeGuard sizeGuard(widget);
  pipeline().setAoEnabled(true);
  pipeline().setEdEnabled(true);
  const std::pair<int, int> sizes[] = {
    { 63, 47 }, { 401, 299 }, { 5, 3 }, { 2, 2 }, { 1, 1 }
  };
  for (const auto& [w, h] : sizes) {
    SCOPED_TRACE(std::to_string(w) + "x" + std::to_string(h));
    widget->resize(w, h);
    settle();
    const QImage image = touchingSpheres(White, Perspective);
    ASSERT_FALSE(image.isNull());
    EXPECT_GE(image.width(), 1);
    // render() checks for GL errors; so does this, for the resize itself.
    widget->makeCurrent();
    EXPECT_EQ(widget->context()->functions()->glGetError(),
              static_cast<GLenum>(GL_NO_ERROR));
    widget->doneCurrent();
    // Nothing in the frame is NaN-black where the sphere should be lit.
    if (image.width() >= 63) {
      const double v = meanLuminance(widget, image, openSurface(), 1);
      EXPECT_GT(v, 20.0);
    }
  }
}

TEST_F(SolidAoTest, survivesResizingLargeToSmallAndBack)
{
  WidgetSizeGuard sizeGuard(widget);
  EXPECT_LT(creviceDarkening(Perspective), 0.85);
  widget->resize(63, 47);
  settle();
  ASSERT_FALSE(touchingSpheres(White, Perspective).isNull());
  widget->resize(640, 480);
  settle();
  EXPECT_LT(creviceDarkening(Perspective), 0.85);
  widget->resize(400, 300);
  settle();
  EXPECT_LT(creviceDarkening(Perspective), 0.85);
}

TEST_F(SolidAoTest, effectsSurviveRendererCleanupAndInitialize)
{
  EXPECT_LT(creviceDarkening(Perspective), 0.85);
  // Without a resize in between, as in a context replacement that keeps the
  // window's size.
  widget->makeCurrent();
  widget->renderer().cleanup();
  widget->renderer().initialize();
  ASSERT_TRUE(widget->renderer().isValid()) << widget->renderer().error();
  widget->doneCurrent();
  EXPECT_LT(creviceDarkening(Perspective), 0.85);
}
