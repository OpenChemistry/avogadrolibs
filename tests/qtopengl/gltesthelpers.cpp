/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "gltesthelpers.h"

#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/camera.h>

#include <gtest/gtest.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QElapsedTimer>
#include <QtGui/QSurfaceFormat>
#include <QtWidgets/QApplication>

#include <algorithm>
#include <cstdlib>
#include <memory>

namespace Avogadro::TestGL {

namespace {

std::unique_ptr<QApplication> ownedApp;
std::unique_ptr<QtOpenGL::GLWidget> widget;
std::string widgetSkipReason;
bool widgetTried = false;

// Destroys the shared widget (with its context current) and the application
// before exit: a function-local static QApplication that has shown a widget is
// destroyed after Qt's thread-local font cache and crashes on the way out.
class Cleanup : public ::testing::Environment
{
public:
  void TearDown() override
  {
    if (widget) {
      widget->makeCurrent();
      widget->renderer().scene().clear();
      widget.reset();
    }
    ownedApp.reset();
  }
};

[[maybe_unused]] const auto* const registered =
  ::testing::AddGlobalTestEnvironment(new Cleanup);

} // namespace

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
  static char arg0[] = "qtopengltests";
  static char* argv[] = { arg0, nullptr };
#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
  // With no display the default platform plugin aborts inside the
  // QApplication constructor, before a suite can skip. Fall back to the
  // offscreen platform, which the GL suites then skip on.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM") &&
      qEnvironmentVariableIsEmpty("DISPLAY") &&
      qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
#endif
  ownedApp = std::make_unique<QApplication>(argc, argv);
  return ownedApp.get();
}

QtOpenGL::GLWidget* sharedWidget(std::string& skipReason)
{
  if (widgetTried) {
    skipReason = widgetSkipReason;
    return widget.get();
  }
  widgetTried = true;

  if (ensureApp() == nullptr) {
    widgetSkipReason = "A QApplication is required for QWidget tests.";
    skipReason = widgetSkipReason;
    return nullptr;
  }
  const QString platform = QGuiApplication::platformName();
  if (platform == "offscreen" || platform == "minimal") {
    widgetSkipReason =
      "No OpenGL context on the " + platform.toStdString() + " platform.";
    skipReason = widgetSkipReason;
    return nullptr;
  }

  widget = std::make_unique<QtOpenGL::GLWidget>();
  widget->resize(400, 300);
  widget->show();

  // Wait for the context and renderer to come up.
  QElapsedTimer timer;
  timer.start();
  while (timer.elapsed() < 5000 && !widget->isValid())
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
  if (!widget->isValid() || widget->context() == nullptr) {
    widgetSkipReason =
      "No usable OpenGL context: " + widget->error().toStdString();
    widget.reset();
  }
  skipReason = widgetSkipReason;
  return widget.get();
}

void settle()
{
  QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
}

void clearScene(QtOpenGL::GLWidget& glWidget)
{
  glWidget.makeCurrent();
  glWidget.renderer().scene().clear();
  glWidget.doneCurrent();
}

void saveForInspection(const QImage& image, const QString& name)
{
  const QByteArray outDir = qgetenv("AVO_TEST_IMAGE_OUT");
  if (!outDir.isEmpty() && !image.isNull())
    image.save(QDir(QString::fromLocal8Bit(outDir)).filePath(name));
}

QPointF screenPoint(QtOpenGL::GLWidget& glWidget, const QImage& image,
                    const Vector3f& scenePoint)
{
  const Rendering::Camera& camera = glWidget.renderer().camera();
  const Vector3f p = camera.project(scenePoint);
  // project() uses OpenGL window coordinates (origin bottom left) in camera
  // units; scale to the grabbed image and flip y.
  const double x = p.x() * image.width() / std::max(1, camera.width());
  const double y =
    image.height() * (1.0 - p.y() / std::max(1, camera.height()));
  return QPointF(x, y);
}

namespace {
template <typename Predicate>
Bounds boundsWhere(const QImage& source, Predicate predicate)
{
  const QImage image = source.convertToFormat(QImage::Format_ARGB32);
  Bounds b;
  b.minX = image.width();
  b.minY = image.height();
  for (int y = 0; y < image.height(); ++y) {
    for (int x = 0; x < image.width(); ++x) {
      const QRgb p = image.pixel(x, y);
      if (!predicate(qRed(p), qGreen(p), qBlue(p)))
        continue;
      b.minX = std::min(b.minX, x);
      b.minY = std::min(b.minY, y);
      b.maxX = std::max(b.maxX, x);
      b.maxY = std::max(b.maxY, y);
      ++b.count;
    }
  }
  return b;
}
} // namespace

Bounds colorBounds(const QImage& image, int r, int g, int b, int tolerance)
{
  return boundsWhere(image, [=](int pr, int pg, int pb) {
    return std::abs(pr - r) <= tolerance && std::abs(pg - g) <= tolerance &&
           std::abs(pb - b) <= tolerance;
  });
}

Bounds dominantBounds(const QImage& image, int channel, int minimum,
                      int maxOther)
{
  return boundsWhere(image, [=](int pr, int pg, int pb) {
    const int c[3] = { pr, pg, pb };
    for (int i = 0; i < 3; ++i) {
      if (i == channel ? c[i] < minimum : c[i] > maxOther)
        return false;
    }
    return true;
  });
}

} // namespace Avogadro::TestGL
