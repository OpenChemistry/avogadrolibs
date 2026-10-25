/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_IMAGESIZEDIALOG_H
#define AVOGADRO_QTOPENGL_IMAGESIZEDIALOG_H

#include "avogadroqtopenglexport.h"
#include "renderoptions.h"

#include <QDialog>
#include <QSize>
#include <QString>

class QCheckBox;
class QSpinBox;

namespace Avogadro {
namespace QtOpenGL {

class GLWidget;

/**
 * @class ImageSizeDialog imagesizedialog.h
 * <avogadro/qtopengl/imagesizedialog.h>
 * @brief Ask for the pixel size of an image or movie rendered from a GLWidget.
 *
 * The size defaults to the last one the user accepted under the same settings
 * key, or else the view size times the device pixel ratio. 1x, 2x and 4x
 * buttons set the size from the view. The width and height can be locked to
 * one aspect ratio.
 */
class AVOGADROQTOPENGL_EXPORT ImageSizeDialog : public QDialog
{
  Q_OBJECT

public:
  /**
   * @param glWidget The view that will be rendered (for the default size).
   * @param settingsKey QSettings group the size is remembered under, so that
   * different uses (images, movies) remember separately.
   * @param showTransparent Show the transparent-background check box.
   * @param evenDimensions Force even width and height (video encoders).
   * @param defaultTransparent Whether the transparent check box starts
   * checked when no earlier choice is remembered.
   */
  ImageSizeDialog(GLWidget* glWidget, const QString& settingsKey,
                  bool showTransparent, bool evenDimensions,
                  QWidget* parent = nullptr, bool defaultTransparent = false);

  /** The chosen size in pixels. */
  QSize imageSize() const;

  /** Whether the user asked for a transparent background. */
  bool transparentBackground() const;

  /** The chosen size and background as render options (Fit framing). */
  RenderOptions renderOptions() const;

  /** Set both dimensions (rounded to even if required, limited to 1-8192). */
  void setImageSize(const QSize& size);

  void accept() override;

private slots:
  void widthEdited(int value);
  void heightEdited(int value);
  void lockToggled(bool locked);

private:
  void dimensionEdited(QSpinBox* changed, QSpinBox* other, int value);
  void updateAspect();
  QSize viewPixelSize() const;
  int normalized(int value) const;
  void applyPreset(int scale);

  GLWidget* m_glWidget;
  QString m_settingsKey;
  bool m_even;
  QSpinBox* m_width;
  QSpinBox* m_height;
  QCheckBox* m_lock;
  QCheckBox* m_transparent; // null unless the check box is offered
  double m_aspect = 1.0;
};

} // namespace QtOpenGL
} // namespace Avogadro

#endif // AVOGADRO_QTOPENGL_IMAGESIZEDIALOG_H
