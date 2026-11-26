/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <gtest/gtest.h>

#include <avogadro/qtopengl/qttextrenderstrategy.h>
#include <avogadro/qtopengl/qttextrenderstrategy_p.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/vector.h>

#include <QtCore/QElapsedTimer>
#include <QtGui/QFont>
#include <QtGui/QImage>
#include <QtWidgets/QApplication>

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using Avogadro::Vector2i;
using Avogadro::QtOpenGL::QtTextRenderStrategy;
using Avogadro::Rendering::TextProperties;
using Avogadro::Rendering::TextRenderStrategy;
using namespace Avogadro::TestGL;

namespace {

struct BBox
{
  int left, right, top, bottom;
  int width() const { return right - left + 1; }
  int height() const { return bottom - top + 1; }
};

// The strategy only needs a QApplication (for fonts), not an OpenGL context,
// so these tests run on every platform, including offscreen.
class QtTextRenderStrategyTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    if (ensureApp() == nullptr)
      GTEST_SKIP() << "A QApplication is required to load fonts.";
  }

  static TextProperties defaultProperties()
  {
    TextProperties tprop;
    tprop.setFontFamily(TextProperties::SansSerif);
    tprop.setPixelHeight(27);
    tprop.setColorRgb(63, 127, 255);
    tprop.setAlign(TextProperties::HLeft, TextProperties::VTop);
    return tprop;
  }

  BBox boundingBox(const std::string& text, const TextProperties& tprop) const
  {
    int b[4];
    strategy.boundingBox(text, tprop, b);
    return { b[0], b[1], b[2], b[3] };
  }

  // Render into an ARGB32 premultiplied buffer sized to the bounding box.
  QImage render(const std::string& text, const TextProperties& tprop,
                std::vector<unsigned char>& buffer, BBox* box = nullptr) const
  {
    const BBox b = boundingBox(text, tprop);
    if (box != nullptr)
      *box = b;
    const Vector2i dims(b.width(), b.height());
    if (dims[0] <= 0 || dims[1] <= 0)
      return QImage();
    buffer.assign(static_cast<size_t>(dims[0]) * dims[1] * 4, 0);
    strategy.render(text, tprop, buffer.data(), dims);
    return QImage(buffer.data(), dims[0], dims[1],
                  QImage::Format_ARGB32_Premultiplied);
  }

  QtTextRenderStrategy strategy;
};

} // namespace

TEST_F(QtTextRenderStrategyTest, newInstance)
{
  QtTextRenderStrategy orig;
  TextRenderStrategy* clone = orig.newInstance();
  ASSERT_NE(clone, nullptr);
  EXPECT_NE(dynamic_cast<QtTextRenderStrategy*>(clone), nullptr);
  EXPECT_NE(clone, &orig);
  delete clone;
}

TEST_F(QtTextRenderStrategyTest, boundingBoxIsCenteredForCenterAlignment)
{
  TextProperties tprop = defaultProperties();
  tprop.setAlign(TextProperties::HCenter, TextProperties::VCenter);
  const BBox b = boundingBox("Testing string\nwith newlines!", tprop);

  EXPECT_GT(b.width(), 0);
  EXPECT_GT(b.height(), 0);
  // Roughly symmetric about the origin (a pixel or two of rounding).
  EXPECT_LE(b.left, 0);
  EXPECT_GE(b.right, 0);
  EXPECT_LE(b.top, 0);
  EXPECT_GE(b.bottom, 0);
  EXPECT_NEAR(b.left + b.right, 0, 3);
  EXPECT_NEAR(b.top + b.bottom, 0, 3);
}

TEST_F(QtTextRenderStrategyTest, boundingBoxIsAnchoredForTopLeftAlignment)
{
  const TextProperties tprop = defaultProperties();
  const BBox b = boundingBox("Testing string", tprop);
  EXPECT_EQ(b.left, 0);
  EXPECT_EQ(b.top, 0);
  EXPECT_GT(b.right, 0);
  EXPECT_GT(b.bottom, 0);
}

TEST_F(QtTextRenderStrategyTest, moreLinesAreTaller)
{
  const TextProperties tprop = defaultProperties();
  const BBox one = boundingBox("Testing string", tprop);
  const BBox two = boundingBox("Testing string\nwith newlines!", tprop);
  const BBox three =
    boundingBox("Testing string\nwith newlines!\nand more", tprop);
  EXPECT_GT(two.height(), one.height());
  EXPECT_GT(three.height(), two.height());
  // About one line height more per line.
  EXPECT_NEAR(two.height(), 2 * one.height(), 0.4 * one.height());
}

TEST_F(QtTextRenderStrategyTest, largerPixelHeightIsLarger)
{
  TextProperties small = defaultProperties();
  small.setPixelHeight(14);
  TextProperties large = defaultProperties();
  large.setPixelHeight(40);
  const BBox s = boundingBox("Testing string", small);
  const BBox l = boundingBox("Testing string", large);
  EXPECT_GT(l.width(), s.width());
  EXPECT_GT(l.height(), s.height());
}

TEST_F(QtTextRenderStrategyTest, wideStringIsWiderThanTall)
{
  const BBox b = boundingBox("Testing string", defaultProperties());
  EXPECT_GT(b.width(), b.height());
}

TEST_F(QtTextRenderStrategyTest, renderDrawsRequestedColor)
{
  TextProperties tprop = defaultProperties();
  tprop.setAlpha(200);
  strategy.setPreserveArgb(true);

  std::vector<unsigned char> buffer;
  BBox box;
  const QImage image =
    render("Testing string\nwith newlines!", tprop, buffer, &box);
  ASSERT_FALSE(image.isNull());
  saveForInspection(image, "qttextrenderstrategy.png");

  int maxAlpha = 0;
  int opaqueish = 0;
  // Un-premultiplied color of well covered pixels.
  long sumR = 0, sumG = 0, sumB = 0;
  int minX = image.width(), minY = image.height(), maxX = -1, maxY = -1;
  for (int y = 0; y < image.height(); ++y) {
    for (int x = 0; x < image.width(); ++x) {
      const QRgb p = image.pixel(x, y);
      const int a = qAlpha(p);
      if (a == 0)
        continue;
      maxAlpha = std::max(maxAlpha, a);
      minX = std::min(minX, x);
      minY = std::min(minY, y);
      maxX = std::max(maxX, x);
      maxY = std::max(maxY, y);
      if (a >= 150) {
        // Premultiplied: color = value * 255 / alpha.
        sumR += qRed(p) * 255 / a;
        sumG += qGreen(p) * 255 / a;
        sumB += qBlue(p) * 255 / a;
        ++opaqueish;
      }
    }
  }

  ASSERT_GT(opaqueish, 20) << "No text pixels were drawn.";
  EXPECT_NEAR(maxAlpha, 200, 3);
  EXPECT_NEAR(static_cast<double>(sumR) / opaqueish, 63, 12);
  EXPECT_NEAR(static_cast<double>(sumG) / opaqueish, 127, 12);
  EXPECT_NEAR(static_cast<double>(sumB) / opaqueish, 255, 12);

  // Everything drawn lies inside the buffer (by construction) and the text
  // fills most of the bounding box rather than a corner of it.
  EXPECT_GT(maxX - minX + 1, 0.6 * box.width());
  EXPECT_GT(maxY - minY + 1, 0.4 * box.height());
}

TEST_F(QtTextRenderStrategyTest, unpreservedBufferIsRgba)
{
  // With the default conversion the bytes are RGBA for OpenGL, so a pure
  // red opaque text has a red component and no blue one in the first and
  // third bytes of its brightest pixels.
  TextProperties tprop = defaultProperties();
  tprop.setColorRgb(255, 0, 0);
  const std::string text("MMMM");
  const BBox b = boundingBox(text, tprop);
  const Vector2i dims(b.width(), b.height());
  std::vector<unsigned char> buffer(static_cast<size_t>(dims[0]) * dims[1] * 4);
  strategy.setPreserveArgb(false);
  strategy.render(text, tprop, buffer.data(), dims);

  int redPixels = 0;
  for (size_t i = 0; i < buffer.size(); i += 4) {
    if (buffer[i + 3] == 255) {
      EXPECT_EQ(buffer[i + 0], 255);
      EXPECT_EQ(buffer[i + 1], 0);
      EXPECT_EQ(buffer[i + 2], 0);
      ++redPixels;
    }
  }
  EXPECT_GT(redPixels, 10);
}

TEST_F(QtTextRenderStrategyTest, rotationByNinetyDegreesSwapsExtent)
{
  TextProperties tprop = defaultProperties();
  const BBox plain = boundingBox("Testing string", tprop);
  tprop.setRotationDegreesCW(90.f);
  const BBox rotated = boundingBox("Testing string", tprop);
  EXPECT_NEAR(rotated.width(), plain.height(), 3);
  EXPECT_NEAR(rotated.height(), plain.width(), 3);

  // The rendered rotated text fits inside its bounding box and is taller than
  // wide.
  strategy.setPreserveArgb(true);
  std::vector<unsigned char> buffer;
  const QImage image = render("Testing string", tprop, buffer);
  ASSERT_FALSE(image.isNull());
  int minX = image.width(), minY = image.height(), maxX = -1, maxY = -1;
  for (int y = 0; y < image.height(); ++y) {
    for (int x = 0; x < image.width(); ++x) {
      if (qAlpha(image.pixel(x, y)) == 0)
        continue;
      minX = std::min(minX, x);
      minY = std::min(minY, y);
      maxX = std::max(maxX, x);
      maxY = std::max(maxY, y);
    }
  }
  ASSERT_GE(maxX, 0) << "No text pixels were drawn.";
  EXPECT_GT(maxY - minY, maxX - minX);
}

namespace {

struct Result
{
  BBox box;
  std::vector<unsigned char> pixels;
};

Result renderAll(const QtTextRenderStrategy& strategy, const std::string& text,
                 const TextProperties& tprop)
{
  Result r;
  int b[4];
  strategy.boundingBox(text, tprop, b);
  r.box = { b[0], b[1], b[2], b[3] };
  const Vector2i dims(r.box.width(), r.box.height());
  if (dims[0] > 0 && dims[1] > 0) {
    r.pixels.assign(static_cast<size_t>(dims[0]) * dims[1] * 4, 0);
    strategy.render(text, tprop, r.pixels.data(), dims);
  }
  return r;
}

bool sameResult(const Result& a, const Result& b)
{
  return a.box.left == b.box.left && a.box.right == b.box.right &&
         a.box.top == b.box.top && a.box.bottom == b.box.bottom &&
         a.pixels == b.pixels;
}

} // namespace

TEST_F(QtTextRenderStrategyTest, preserveArgbDefaultsToFalse)
{
  for (int i = 0; i < 20; ++i) {
    QtTextRenderStrategy fresh;
    EXPECT_FALSE(fresh.preserveArgb());
    std::unique_ptr<TextRenderStrategy> clone(fresh.newInstance());
    auto* q = dynamic_cast<QtTextRenderStrategy*>(clone.get());
    ASSERT_NE(q, nullptr);
    EXPECT_FALSE(q->preserveArgb());
  }
}

TEST_F(QtTextRenderStrategyTest, cachedFontsMatchUncachedAndAreStable)
{
  using namespace Avogadro::QtOpenGL::Detail;
  const TextProperties::FontFamily families[] = { TextProperties::SansSerif,
                                                  TextProperties::Serif,
                                                  TextProperties::Mono };
  const int styleSets[] = { 0, TextProperties::Bold, TextProperties::Italic,
                            TextProperties::Underline,
                            TextProperties::Bold | TextProperties::Italic |
                              TextProperties::Underline };
  const float rotations[] = { 0.f, 90.f, 33.f };
  clearFontCache();
  for (int pass = 0; pass < 2; ++pass) { // pass 0 cold, pass 1 warm
    for (auto family : families) {
      for (size_t height : { 9, 14, 27, 40 }) {
        for (int styles : styleSets) {
          for (float rot : rotations) {
            TextProperties tprop = defaultProperties();
            tprop.setFontFamily(family);
            tprop.setPixelHeight(height);
            tprop.setFontStyles(styles);
            tprop.setRotationDegreesCW(rot);
            EXPECT_EQ(scaledFontCached(tprop), scaledFontUncached(tprop));
            const Result first = renderAll(strategy, "CA 1234", tprop);
            const Result again = renderAll(strategy, "CA 1234", tprop);
            EXPECT_TRUE(sameResult(first, again));
            // A cold cache gives the same pixels as the warm one.
            clearFontCache();
            const Result cold = renderAll(strategy, "CA 1234", tprop);
            EXPECT_TRUE(sameResult(first, cold));
          }
        }
      }
    }
  }
}

TEST_F(QtTextRenderStrategyTest, fontCacheIsBoundedAndEvictionIsCorrect)
{
  using namespace Avogadro::QtOpenGL::Detail;
  clearFontCache();
  const size_t limit = fontCacheLimit();
  std::vector<Result> results;
  for (size_t h = 8; h < 8 + 3 * limit; ++h) {
    TextProperties tprop = defaultProperties();
    tprop.setPixelHeight(h);
    results.push_back(renderAll(strategy, "CA", tprop));
    EXPECT_LE(fontCacheSize(), limit);
  }
  // Revisit everything after evictions: same output, and equal to uncached.
  for (size_t h = 8; h < 8 + 3 * limit; ++h) {
    TextProperties tprop = defaultProperties();
    tprop.setPixelHeight(h);
    EXPECT_TRUE(sameResult(results[h - 8], renderAll(strategy, "CA", tprop)));
    EXPECT_EQ(scaledFontCached(tprop), scaledFontUncached(tprop));
  }
}

TEST_F(QtTextRenderStrategyTest, applicationFontChangeIsNotStale)
{
  using namespace Avogadro::QtOpenGL::Detail;
  // On macOS SansSerif resolves to QApplication::font().family() at call
  // time, so changing the application font must produce a new cache entry. On
  // other platforms SansSerif is the literal "SansSerif", so this only checks
  // that the cached result still equals the uncached one after the change.
  const QFont original = QApplication::font();
  TextProperties tprop = defaultProperties();
  clearFontCache();
  const Result before = renderAll(strategy, "CA", tprop);

  QFont other = original;
  other.setFamily("Courier");
  QApplication::setFont(other);
  EXPECT_EQ(scaledFontCached(tprop), scaledFontUncached(tprop));
  const Result changed = renderAll(strategy, "CA", tprop);
  clearFontCache();
  EXPECT_TRUE(sameResult(changed, renderAll(strategy, "CA", tprop)));

  QApplication::setFont(original);
  EXPECT_EQ(scaledFontCached(tprop), scaledFontUncached(tprop));
  EXPECT_TRUE(sameResult(before, renderAll(strategy, "CA", tprop)));
}

// Reports the cost of building label textures. Disabled by default; run with
// --gtest_also_run_disabled_tests. Nothing here asserts on time.
TEST_F(QtTextRenderStrategyTest, DISABLED_reportLabelTiming)
{
  const std::vector<std::string> labels = { "C", "H", "O", "N", "CA", "1234" };
  const std::vector<size_t> heights = { 12, 20, 36 };
  for (int count : { 1000, 10000 }) {
    std::vector<double> perCall;
    for (int run = 0; run < 5; ++run) {
      std::vector<unsigned char> buffer;
      QElapsedTimer timer;
      timer.start();
      for (int i = 0; i < count; ++i) {
        TextProperties tprop = defaultProperties();
        tprop.setPixelHeight(heights[static_cast<size_t>(i) % heights.size()]);
        const std::string& text =
          labels[static_cast<size_t>(i) % labels.size()];
        const BBox b = boundingBox(text, tprop);
        const Vector2i dims(b.width(), b.height());
        buffer.assign(static_cast<size_t>(dims[0]) * dims[1] * 4, 0);
        strategy.render(text, tprop, buffer.data(), dims);
      }
      // Two strategy calls per label.
      perCall.push_back(static_cast<double>(timer.nsecsElapsed()) / 1000.0 /
                        (2.0 * count));
    }
    std::sort(perCall.begin(), perCall.end());
    std::cout << "labels=" << count << " median us/call=" << perCall[2]
              << " (min " << perCall[0] << ", max " << perCall[4] << ")\n";
  }
}
