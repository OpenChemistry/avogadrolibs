/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtGui/QSurfaceFormat>
#include <QtWidgets/QApplication>

#include <gtest/gtest.h>

// One QApplication for the whole binary, created before any test runs. The
// tests used to create their own in a per-file ensureApp(), so which kind of
// application a test got -- and whether the widget and OpenGL tests had to
// skip -- depended on which test file ran first.
int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);

#if !defined(Q_OS_WIN) && !defined(Q_OS_MACOS)
  // With no display the default platform plugin aborts inside the
  // QApplication constructor. Fall back to the offscreen platform, on which
  // the tests that need an OpenGL context skip themselves. Windows and macOS
  // always have a (headless-capable) platform plugin; CTest or the caller can
  // still set QT_QPA_PLATFORM to override.
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM") &&
      qEnvironmentVariableIsEmpty("DISPLAY") &&
      qEnvironmentVariableIsEmpty("WAYLAND_DISPLAY"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
#endif

  // Same context request as the application, for the tests that make a
  // GLWidget. Must be set before the QApplication is constructed.
  QSurfaceFormat format = QSurfaceFormat::defaultFormat();
  format.setVersion(4, 0);
  format.setProfile(QSurfaceFormat::CoreProfile);
  format.setDepthBufferSize(24);
  format.setStencilBufferSize(8);
  QSurfaceFormat::setDefaultFormat(format);

  QApplication app(argc, argv);
  // QSettings files nothing without these (on Windows, in particular).
  QCoreApplication::setOrganizationName("OpenChemistry");
  QCoreApplication::setApplicationName("AvogadroLibsTests");

  return RUN_ALL_TESTS();
}
