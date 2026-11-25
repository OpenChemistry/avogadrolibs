/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_QTOPENGL_GLTESTHELPERS_H
#define AVOGADRO_TESTS_QTOPENGL_GLTESTHELPERS_H

#include <avogadro/core/vector.h>
#include <avogadro/rendering/avogadrogl.h>

#include <QtCore/QPointF>
#include <QtCore/QString>
#include <QtGui/QImage>

#include <string>

class QApplication;

namespace Avogadro::QtOpenGL {
class GLWidget;
}

namespace Avogadro::TestGL {

/**
 * Create the QApplication (with the same GL 4.0 core format request as the
 * application) if there is none yet. It lives until the end of the test run.
 */
QApplication* ensureApp();

/**
 * Returns the GLWidget shared by every GL suite in this executable, creating
 * and showing it on first use, or nullptr if there is no usable OpenGL context.
 * In that case skipReason is set to a message suitable for GTEST_SKIP().
 */
QtOpenGL::GLWidget* sharedWidget(std::string& skipReason);

/**
 * Discard pending GL errors, with the widget's context current. Bounded
 * because some drivers report an error forever.
 */
inline void drainGLErrors()
{
  for (int i = 0; i < 32 && glGetError() != GL_NO_ERROR; ++i) {}
}

/** Let queued scene updates and repaints run. */
void settle();

/** Remove everything from the widget's scene, with its context current. */
void clearScene(QtOpenGL::GLWidget& widget);

/** If AVO_TEST_IMAGE_OUT names a directory, save the image there. */
void saveForInspection(const QImage& image, const QString& name);

/** The image position (origin top left) of a scene point under the camera. */
QPointF screenPoint(QtOpenGL::GLWidget& widget, const QImage& image,
                    const Vector3f& scenePoint);

/** Bounding box (inclusive, origin top left) of a set of matched pixels. */
struct Bounds
{
  int minX = 0, minY = 0, maxX = -1, maxY = -1;
  int count = 0;
  bool empty() const { return count == 0; }
  double centerX() const { return 0.5 * (minX + maxX + 1); }
  double centerY() const { return 0.5 * (minY + maxY + 1); }
};

/**
 * Bounds of the pixels whose color is close to the given one: each channel
 * within tolerance of the target.
 */
Bounds colorBounds(const QImage& image, int r, int g, int b, int tolerance);

/**
 * Bounds of the pixels where the given channel (0 red, 1 green, 2 blue) is at
 * least minimum and both other channels are at most maxOther.
 */
Bounds dominantBounds(const QImage& image, int channel, int minimum,
                      int maxOther);

} // namespace Avogadro::TestGL

#endif // AVOGADRO_TESTS_QTOPENGL_GLTESTHELPERS_H
