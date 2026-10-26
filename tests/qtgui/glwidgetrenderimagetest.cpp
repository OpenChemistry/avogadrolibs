/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/vector.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/qtopengl/renderoptions.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/meshgeometry.h>
#include <avogadro/rendering/spheregeometry.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtGui/QImage>
#include <QtGui/QSurfaceFormat>
#include <QtWidgets/QApplication>

#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::QtOpenGL::RenderOptions;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Rendering::SphereGeometry;

namespace {

const Vector4ub Background(40, 80, 120, 255);

std::unique_ptr<QApplication> ownedApp;

QApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QApplication*>(QCoreApplication::instance());

  // Same context request as the application.
  QSurfaceFormat format = QSurfaceFormat::defaultFormat();
  format.setVersion(4, 0);
  format.setProfile(QSurfaceFormat::CoreProfile);
  format.setDepthBufferSize(24);
  format.setStencilBufferSize(8);
  QSurfaceFormat::setDefaultFormat(format);

  static int argc = 1;
  static char arg0[] = "glwidgetrenderimagetest";
  static char* argv[] = { arg0, nullptr };
#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
  // With no display the default platform plugin aborts inside the
  // QApplication constructor, before the suite can skip. Fall back to the
  // offscreen platform, which SetUpTestSuite() then skips on.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM") &&
      qEnvironmentVariableIsEmpty("DISPLAY") &&
      qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
#endif
  // Heap allocated and destroyed by the fixture before exit: a function-local
  // static QApplication that has shown a widget is destroyed after Qt's
  // thread-local font cache and crashes on the way out.
  ownedApp = std::make_unique<QApplication>(argc, argv);
  return ownedApp.get();
}

struct Bounds
{
  int minX, minY, maxX, maxY;
  bool empty;
};

// Bounding box of the pixels that differ from the background colour.
Bounds objectBounds(const QImage& image)
{
  Bounds b{ image.width(), image.height(), -1, -1, true };
  const QRgb bg = qRgb(Background[0], Background[1], Background[2]);
  for (int y = 0; y < image.height(); ++y) {
    for (int x = 0; x < image.width(); ++x) {
      QRgb p = image.pixel(x, y);
      if (std::abs(qRed(p) - qRed(bg)) > 8 ||
          std::abs(qGreen(p) - qGreen(bg)) > 8 ||
          std::abs(qBlue(p) - qBlue(bg)) > 8) {
        b.minX = std::min(b.minX, x);
        b.minY = std::min(b.minY, y);
        b.maxX = std::max(b.maxX, x);
        b.maxY = std::max(b.maxY, y);
        b.empty = false;
      }
    }
  }
  return b;
}

double meanAbsDiff(const QImage& a, const QImage& b)
{
  QImage ia = a.convertToFormat(QImage::Format_RGB32);
  QImage ib = b.convertToFormat(QImage::Format_RGB32);
  if (ia.size() != ib.size())
    return 1e9;
  double sum = 0.0;
  for (int y = 0; y < ia.height(); ++y) {
    for (int x = 0; x < ia.width(); ++x) {
      QRgb p = ia.pixel(x, y), q = ib.pixel(x, y);
      sum += std::abs(qRed(p) - qRed(q)) + std::abs(qGreen(p) - qGreen(q)) +
             std::abs(qBlue(p) - qBlue(q));
    }
  }
  return sum / (3.0 * ia.width() * ia.height());
}

// The largest difference in any one channel of any pixel.
int maxAbsDiff(const QImage& a, const QImage& b)
{
  QImage ia = a.convertToFormat(QImage::Format_RGB32);
  QImage ib = b.convertToFormat(QImage::Format_RGB32);
  if (ia.size() != ib.size())
    return 1 << 30;
  int maxDiff = 0;
  for (int y = 0; y < ia.height(); ++y) {
    for (int x = 0; x < ia.width(); ++x) {
      QRgb p = ia.pixel(x, y), q = ib.pixel(x, y);
      maxDiff = std::max({ maxDiff, std::abs(qRed(p) - qRed(q)),
                           std::abs(qGreen(p) - qGreen(q)),
                           std::abs(qBlue(p) - qBlue(q)) });
    }
  }
  return maxDiff;
}

// Let queued scene updates and repaints run.
void settle()
{
  QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
}

void clearScene(GLWidget& widget)
{
  widget.makeCurrent();
  widget.renderer().scene().clear();
  widget.doneCurrent();
}

class GLWidgetRenderImageTest : public ::testing::Test
{
protected:
  // One widget (and so one context) is shared by the whole suite. Tearing a
  // widget down with no context current frees its GL objects blind, which can
  // disturb the next context on some drivers.
  static void SetUpTestSuite()
  {
    skipReason.clear();
    if (ensureApp() == nullptr) {
      skipReason = "A QApplication is required for QWidget tests.";
      return;
    }
    const QString platform = QGuiApplication::platformName();
    if (platform == "offscreen" || platform == "minimal") {
      skipReason =
        "No OpenGL context on the " + platform.toStdString() + " platform.";
      return;
    }

    widget = std::make_unique<GLWidget>();
    widget->resize(400, 300);
    widget->show();

    // Wait for the context and renderer to come up.
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 5000 && !widget->isValid()) {
      QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    }
    if (!widget->isValid() || widget->context() == nullptr) {
      skipReason = "No usable OpenGL context: " + widget->error().toStdString();
      widget.reset();
      return;
    }
    // The application keeps the pipeline's fog colour in step with the scene
    // background.
    widget->renderer().solidPipeline().setBackgroundColor(Background);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
  }

  static void TearDownTestSuite()
  {
    if (widget) {
      widget->makeCurrent();
      widget->renderer().scene().clear();
      widget.reset();
    }
    ownedApp.reset();
  }

  void SetUp() override
  {
    if (!widget)
      GTEST_SKIP() << skipReason;

    // Fresh scene: a small cluster of spheres, added directly.
    clearScene(*widget);
    auto* geometry = new GeometryNode;
    auto* spheres = new SphereGeometry;
    geometry->addDrawable(spheres);
    spheres->addSphere(Vector3f(-1.2f, 0, 0), Vector3ub(220, 40, 40), 0.8f);
    spheres->addSphere(Vector3f(1.2f, 0, 0), Vector3ub(240, 240, 240), 0.8f);
    spheres->addSphere(Vector3f(0, 1.2f, 0), Vector3ub(40, 220, 40), 0.8f);
    spheres->addSphere(Vector3f(0, -1.2f, 0), Vector3ub(240, 200, 40), 0.8f);
    widget->renderer().scene().rootNode().addChild(geometry);
    widget->renderer().scene().setBackgroundColor(Background);
    widget->renderer().resetGeometry();
    widget->renderer().resetCamera();
    settle();
  }

  QImage render(int w, int h, bool transparent = false, int supersample = 1,
                RenderOptions::Framing framing = RenderOptions::Framing::Fit,
                const char* saveAs = nullptr)
  {
    RenderOptions options;
    options.size = QSize(w, h);
    options.transparentBackground = transparent;
    options.supersample = supersample;
    options.framing = framing;
    QString error;
    QImage image = widget->renderImage(options, &error);
    EXPECT_FALSE(image.isNull()) << error.toStdString();
    EXPECT_TRUE(error.isEmpty());
    const char* outDir = std::getenv("AVO_RENDERIMAGE_OUT");
    if (outDir != nullptr && saveAs != nullptr && !image.isNull())
      image.save(QDir(outDir).filePath(saveAs));
    return image;
  }

  static std::unique_ptr<GLWidget> widget;
  static std::string skipReason;
};

std::unique_ptr<GLWidget> GLWidgetRenderImageTest::widget;
std::string GLWidgetRenderImageTest::skipReason;

} // namespace

TEST_F(GLWidgetRenderImageTest, exactOutputSizes)
{
  const QSize sizes[] = { { 300, 300 },   { 900, 300 },  { 300, 900 },
                          { 401, 333 },   { 1001, 999 }, { 7, 5 },
                          { 1920, 1080 }, { 640, 480 },  { 3000, 1963 },
                          { 1963, 3000 }, { 8192, 3 },   { 3, 4000 } };
  for (const QSize& size : sizes) {
    QImage image = render(size.width(), size.height());
    EXPECT_EQ(image.size(), size);
    EXPECT_DOUBLE_EQ(image.devicePixelRatio(), 1.0);
    EXPECT_EQ(image.format(), QImage::Format_RGB32);
  }
}

TEST_F(GLWidgetRenderImageTest, defaultSizeIsViewTimesPixelRatio)
{
  RenderOptions options;
  QString error;
  QImage image = widget->renderImage(options, &error);
  ASSERT_FALSE(image.isNull()) << error.toStdString();
  const qreal dpr = widget->devicePixelRatioF();
  EXPECT_EQ(image.width(), qRound(widget->width() * dpr));
  EXPECT_EQ(image.height(), qRound(widget->height() * dpr));
}

TEST_F(GLWidgetRenderImageTest, supersampleGivesRequestedSize)
{
  QImage image = render(300, 200, false, 2);
  EXPECT_EQ(image.size(), QSize(300, 200));
  image = render(300, 200, false, 4);
  EXPECT_EQ(image.size(), QSize(300, 200));
}

TEST_F(GLWidgetRenderImageTest, transparentCornerHasNoAlpha)
{
  QImage image =
    render(400, 300, true, 1, RenderOptions::Framing::Fit, "transparent.png");
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(image.format(), QImage::Format_ARGB32);
  EXPECT_EQ(qAlpha(image.pixel(0, 0)), 0);
  EXPECT_EQ(qAlpha(image.pixel(399, 299)), 0);
  // The objects themselves are opaque.
  int maxAlpha = 0;
  for (int y = 0; y < image.height(); ++y)
    for (int x = 0; x < image.width(); ++x)
      maxAlpha = std::max(maxAlpha, qAlpha(image.pixel(x, y)));
  EXPECT_EQ(maxAlpha, 255);
}

TEST_F(GLWidgetRenderImageTest, opaqueCornerIsBackground)
{
  QImage image = render(400, 300);
  ASSERT_FALSE(image.isNull());
  for (QPoint p :
       { QPoint(0, 0), QPoint(399, 0), QPoint(0, 299), QPoint(399, 299) }) {
    QRgb c = image.pixel(p);
    EXPECT_EQ(qAlpha(c), 255);
    EXPECT_NEAR(qRed(c), Background[0], 1);
    EXPECT_NEAR(qGreen(c), Background[1], 1);
    EXPECT_NEAR(qBlue(c), Background[2], 1);
  }
}

TEST_F(GLWidgetRenderImageTest, fitKeepsObjectInsideAndCentred)
{
  struct Case
  {
    int w, h;
    const char* name;
  };
  const Case cases[] = { { 400, 300, "view.png" },
                         { 1200, 400, "wide.png" },
                         { 400, 1200, "tall.png" },
                         { 300, 300, "square.png" } };
  for (const Case& c : cases) {
    QImage image =
      render(c.w, c.h, false, 1, RenderOptions::Framing::Fit, c.name);
    ASSERT_FALSE(image.isNull());
    Bounds b = objectBounds(image);
    ASSERT_FALSE(b.empty) << c.name;
    EXPECT_GT(b.minX, 0) << c.name;
    EXPECT_GT(b.minY, 0) << c.name;
    EXPECT_LT(b.maxX, c.w - 1) << c.name;
    EXPECT_LT(b.maxY, c.h - 1) << c.name;
    const double cx = 0.5 * (b.minX + b.maxX + 1);
    const double cy = 0.5 * (b.minY + b.maxY + 1);
    EXPECT_NEAR(cx, c.w / 2.0, 0.03 * c.w) << c.name;
    EXPECT_NEAR(cy, c.h / 2.0, 0.03 * c.h) << c.name;
  }
}

TEST_F(GLWidgetRenderImageTest, matchHeightCropsTallOutput)
{
  QImage fit = render(300, 900, false, 1, RenderOptions::Framing::Fit);
  QImage match = render(300, 900, false, 1, RenderOptions::Framing::MatchHeight,
                        "tall-match.png");
  Bounds bf = objectBounds(fit);
  Bounds bm = objectBounds(match);
  ASSERT_FALSE(bf.empty);
  ASSERT_FALSE(bm.empty);
  // Fit shows the whole view width, so the object is much smaller.
  EXPECT_LT(bf.maxX - bf.minX, bm.maxX - bm.minX);
  // MatchHeight keeps today's vertical extent.
  EXPECT_GT(bm.maxY - bm.minY, bf.maxY - bf.minY);
}

TEST_F(GLWidgetRenderImageTest, resolutionIndependent)
{
  QImage small = render(400, 400);
  QImage large = render(1600, 1600);
  ASSERT_FALSE(small.isNull());
  ASSERT_FALSE(large.isNull());
  QImage reduced =
    large.scaled(small.size(), Qt::IgnoreAspectRatio, Qt::SmoothTransformation);
  const double diff = meanAbsDiff(small, reduced);
  EXPECT_LT(diff, 6.0);

  QImage super = render(400, 400, false, 4);
  const double superDiff = meanAbsDiff(super, reduced);
  EXPECT_LT(superDiff, 6.0);
}

TEST_F(GLWidgetRenderImageTest, restoresWidgetState)
{
  auto& renderer = widget->renderer();
  const int camW = renderer.camera().width();
  const int camH = renderer.camera().height();
  const float ratio = renderer.pixelRatio();
  const float scale = renderer.projectionScale();
  const Vector4ub background = renderer.scene().backgroundColor();
  const Eigen::Matrix4f modelView = renderer.camera().modelView().matrix();
  const QSize widgetSize = widget->size();

  QImage before = widget->grabFramebuffer();
  ASSERT_FALSE(before.isNull());

  QImage image = render(1200, 300);
  ASSERT_FALSE(image.isNull());

  EXPECT_EQ(renderer.camera().width(), camW);
  EXPECT_EQ(renderer.camera().height(), camH);
  EXPECT_FLOAT_EQ(renderer.pixelRatio(), ratio);
  EXPECT_FLOAT_EQ(renderer.projectionScale(), scale);
  EXPECT_EQ(renderer.scene().backgroundColor(), background);
  EXPECT_TRUE(renderer.camera().modelView().matrix().isApprox(modelView));
  EXPECT_EQ(widget->size(), widgetSize);

  // The on-screen render is unchanged.
  QImage after = widget->grabFramebuffer();
  ASSERT_FALSE(after.isNull());
  EXPECT_EQ(before.size(), after.size());
  EXPECT_EQ(meanAbsDiff(before, after), 0.0);
}

TEST_F(GLWidgetRenderImageTest, failurePaths)
{
  auto& renderer = widget->renderer();
  const float ratio = renderer.pixelRatio();
  struct Case
  {
    QSize size;
    int supersample;
  };
  const Case cases[] = { { { 0, 100 }, 1 },
                         { { 100, 0 }, 1 },
                         { { -5, 100 }, 1 },
                         { { 100, 100 }, 0 },
                         { { 100, 100 }, 5 },
                         { { 100, 100 }, -1 },
                         { { 8193, 100 }, 1 },
                         { { 100, 9000 }, 1 },
                         { { 2049, 100 }, 4 },
                         { { 100000, 100000 }, 1 },
                         { { 2147483647, 2147483647 }, 4 } };
  for (const Case& c : cases) {
    RenderOptions options;
    options.size = c.size;
    options.supersample = c.supersample;
    QString error;
    QImage image = widget->renderImage(options, &error);
    EXPECT_TRUE(image.isNull()) << c.size.width() << "x" << c.size.height();
    EXPECT_FALSE(error.isEmpty());
  }
  // None of that disturbed the widget, and it still renders.
  EXPECT_FLOAT_EQ(renderer.pixelRatio(), ratio);
  EXPECT_FALSE(render(200, 100).isNull());
}

TEST_F(GLWidgetRenderImageTest, widgetWithoutContextFails)
{
  GLWidget unshown;
  RenderOptions options;
  options.size = QSize(100, 100);
  QString error;
  QImage image = unshown.renderImage(options, &error);
  EXPECT_TRUE(image.isNull());
  EXPECT_FALSE(error.isEmpty());
}

TEST_F(GLWidgetRenderImageTest, emptySceneIsBackground)
{
  clearScene(*widget);
  QImage image = render(320, 200);
  ASSERT_FALSE(image.isNull());
  EXPECT_TRUE(objectBounds(image).empty);
}

TEST_F(GLWidgetRenderImageTest, repeatedCallsAreStable)
{
  QImage first = render(500, 250);
  for (int i = 0; i < 6; ++i) {
    QImage again = render(500 + 10 * (i % 2), 250);
    if (i % 2 == 0)
      EXPECT_EQ(meanAbsDiff(first, again), 0.0);
  }
  QImage last = render(500, 250);
  EXPECT_EQ(meanAbsDiff(first, last), 0.0);
}

// Adds a translucent, pure red quad facing the camera. It covers the middle of
// the view, partly over the spheres (if any) and partly over the background.
void addTranslucentQuad(GLWidget& widget, unsigned char opacity)
{
  auto* node = new GeometryNode;
  auto* mesh = new MeshGeometry;
  node->addDrawable(mesh);
  mesh->setRenderPass(Avogadro::Rendering::TranslucentPass);
  mesh->setColor(Vector3ub(255, 0, 0));
  mesh->setOpacity(opacity);
  Avogadro::Core::Array<Vector3f> vertices, normals;
  const float h = 2.6f, z = 1.5f;
  vertices.push_back(Vector3f(-h, -h, z));
  vertices.push_back(Vector3f(h, -h, z));
  vertices.push_back(Vector3f(h, h, z));
  vertices.push_back(Vector3f(-h, h, z));
  for (int i = 0; i < 4; ++i)
    normals.push_back(Vector3f(0, 0, 1));
  const unsigned int first = mesh->addVertices(vertices, normals);
  mesh->addTriangle(first, first + 1, first + 2);
  mesh->addTriangle(first, first + 2, first + 3);
  widget.renderer().scene().rootNode().addChild(node);
  widget.renderer().resetGeometry();
  widget.renderer().resetCamera();
  settle();
}

TEST_F(GLWidgetRenderImageTest, translucentAloneKeepsPartialAlpha)
{
  clearScene(*widget);
  addTranslucentQuad(*widget, 128);

  QImage image = render(400, 300, true, 1, RenderOptions::Framing::Fit,
                        "translucent-transparent.png");
  ASSERT_FALSE(image.isNull());
  EXPECT_EQ(image.format(), QImage::Format_ARGB32);
  // The centre of the quad covers only background.
  const QRgb c = image.pixel(200, 150);
  EXPECT_GT(qAlpha(c), 10);
  EXPECT_LT(qAlpha(c), 245);
  EXPECT_NEAR(qAlpha(c), 128, 20);
  // Pure red stays red once un-premultiplied. A face-on normal receives only
  // the mesh shader's ambient term, 255 / 2.2 = 116; a colour blended against
  // black first would read about half of that.
  EXPECT_NEAR(qRed(c), 116, 12);
  EXPECT_LT(qGreen(c), 25);
  EXPECT_LT(qBlue(c), 25);
  EXPECT_EQ(qAlpha(image.pixel(0, 0)), 0);
}

TEST_F(GLWidgetRenderImageTest, opaqueMatchesWindowWithTranslucent)
{
  addTranslucentQuad(*widget, 128);
  const Vector4ub white(255, 255, 255, 255);
  widget->renderer().scene().setBackgroundColor(white);
  widget->renderer().solidPipeline().setBackgroundColor(white);
  settle();

  QImage window = widget->grabFramebuffer();
  ASSERT_FALSE(window.isNull());
  window.setDevicePixelRatio(1.0);
  QImage exported = widget->renderImage(RenderOptions());
  ASSERT_FALSE(exported.isNull());
  ASSERT_EQ(window.size(), exported.size());
  EXPECT_EQ(exported.format(), QImage::Format_RGB32);

  const QImage b = exported.convertToFormat(QImage::Format_RGB32);
  const int maxDiff = maxAbsDiff(window, exported);
  EXPECT_LE(maxDiff, 2);
  // Not a trivial comparison: the quad tints the white background.
  EXPECT_LT(qGreen(b.pixel(b.width() / 2, b.height() / 2)), 200);

  widget->renderer().solidPipeline().setBackgroundColor(Background);
}

// The export of the opaque scene agrees with the frame the widget itself draws
// with each screen-space effect on.
TEST_F(GLWidgetRenderImageTest, exportMatchesWindow)
{
  auto& pipeline = widget->renderer().solidPipeline();
  const bool ao = pipeline.getAoEnabled();
  const bool ed = pipeline.getEdEnabled();
  const bool dof = pipeline.getDofEnabled();
  const bool fog = pipeline.getFogEnabled();

  struct Config
  {
    const char* name;
    bool fog, ao, ed, dof;
  };
  const Config configs[] = { { "none", false, false, false, false },
                             { "fog", true, false, false, false },
                             { "fog+ao", true, true, false, false },
                             { "fog+edge", true, false, true, false },
                             { "fog+dof", true, false, false, true },
                             { "all", true, true, true, true } };
  for (const Config& c : configs) {
    pipeline.setFogEnabled(c.fog);
    pipeline.setAoEnabled(c.ao);
    pipeline.setEdEnabled(c.ed);
    pipeline.setDofEnabled(c.dof);

    QImage direct = widget->grabFramebuffer();
    ASSERT_FALSE(direct.isNull());
    direct.setDevicePixelRatio(1.0);
    QImage exported = widget->renderImage(RenderOptions()); // view x DPR
    ASSERT_FALSE(exported.isNull());
    ASSERT_EQ(direct.size(), exported.size());
    // Same layout as the widget, so these should agree closely.
    EXPECT_LT(meanAbsDiff(direct, exported), 2.0) << c.name;
  }

  pipeline.setFogEnabled(fog);
  pipeline.setAoEnabled(ao);
  pipeline.setEdEnabled(ed);
  pipeline.setDofEnabled(dof);
}
