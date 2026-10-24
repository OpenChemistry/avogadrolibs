/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTOPENGL_RENDEROPTIONS_H
#define AVOGADRO_QTOPENGL_RENDEROPTIONS_H

#include <QSize>

namespace Avogadro::QtOpenGL {

/**
 * @struct RenderOptions renderoptions.h <avogadro/qtopengl/renderoptions.h>
 * @brief Options for GLWidget::renderImage().
 */
struct RenderOptions
{
  /** Output size in pixels. An invalid size means the view size times the
   *  widget's device pixel ratio. */
  QSize size;

  /** Leave the background transparent (ARGB output). Otherwise the image is
   *  composited over the view's background colour and is opaque. */
  bool transparentBackground = false;

  /** How to frame the scene when the output aspect ratio differs from the
   *  view's. */
  enum class Framing
  {
    /** Never crop what the view shows: a narrower output zooms out. */
    Fit,
    /** Keep the view's vertical extent: a narrower output crops the sides. */
    MatchHeight
  };
  Framing framing = Framing::Fit;

  /** 1-4: render this many times larger, then downsample to size. */
  int supersample = 1;
};

} // namespace Avogadro::QtOpenGL

#endif // AVOGADRO_QTOPENGL_RENDEROPTIONS_H
