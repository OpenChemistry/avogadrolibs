/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDPIPELINE_H
#define AVOGADRO_RENDERING_SOLIDPIPELINE_H

#include "avogadrorenderingexport.h"
#include "camera.h"

namespace Avogadro::Rendering {

class AVOGADRORENDERING_EXPORT SolidPipeline
{
public:
  SolidPipeline();
  ~SolidPipeline();

  /**
   * @brief Probably don't want to support copy/assignment.
   */
  SolidPipeline(const SolidPipeline&) = delete;
  SolidPipeline& operator=(const SolidPipeline&) = delete;

  /**
   * @brief Initialize OpenGL objects.
   */
  void initialize();

  /**
   * @brief Release OpenGL objects while the owning context is current.
   *
   * Safe to call repeatedly; it deletes only non-zero names. The owner must
   * call it with the context current before that context goes away.
   */
  void releaseResources();

  /**
   * @brief True if any screen-space post-processing effect is enabled.
   *
   * When false, begin() returns false so solid geometry renders directly to
   * the active framebuffer without an offscreen pass.
   */
  bool hasActiveEffects() const
  {
    return m_aoEnabled || m_edEnabled || m_fogEnabled || m_dofEnabled;
  }

  /**
   * @brief Begin solid geometry rendering. Returns false if unavailable or if
   * no post-processing effect is enabled.
   */
  bool begin();

  void adjustOffset(const Camera& camera);

  /**
   * @brief End solid geometry rendering and apply screen-space shaders.
   *
   * The camera is needed by the ambient occlusion blur, which turns window
   * depth back into scene units to tell surfaces apart.
   */
  void end(const Camera& camera);

  /**
   * @brief Resize buffers for width x height viewport.
   */
  void resize(int width, int height);

  /**
   * @brief Resize buffers to exactly deviceWidth x deviceHeight pixels.
   */
  void resizeDevice(int deviceWidth, int deviceHeight);

  /**
   * @brief Set pixel ratio (1.0 on standard displays, 2.0 on Retina, etc.).
   */
  void setPixelRatio(float ratio);

  /**
   * @brief Get or set whether Ambient Occlusion is enabled.
   */
  bool getAoEnabled() { return m_aoEnabled; }
  void setAoEnabled(bool enabled) { m_aoEnabled = enabled; }

  /**
   * @brief Get or set whether Depth-of-feild is enabled.
   */
  bool getDofEnabled() { return m_dofEnabled; }
  void setDofEnabled(bool enabled) { m_dofEnabled = enabled; }

  /**
   * @brief Get or set whether Fog is enabled.
   */
  bool getFogEnabled() { return m_fogEnabled; }
  void setFogEnabled(bool enabled) { m_fogEnabled = enabled; }

  /**
   * @brief Set Background Color to it's current value.
   */
  Vector4ub backgroundColor() const { return m_backgroundColor; }
  void setBackgroundColor(const Vector4ub& c) { m_backgroundColor = c; }

  /**
   * @brief Get or set shadow strength for Ambient Occlusion.
   */
  float getAoStrength() { return m_aoStrength; }
  void setAoStrength(float strength) { m_aoStrength = strength; }

  /**
   * @brief Get or set fog strength.
   */
  float getFogStrength() { return m_fogStrength; }
  void setFogStrength(float strength) { m_fogStrength = strength; }

  /**
   * @brief Get or set fog position
   */
  float getFogPosition() { return m_fogPosition; }
  void setFogPosition(float position) { m_fogPosition = position; }

  /**
   * @brief Get or set whether Edge Detection is enabled.
   *
   * Enabling leaves the strength alone, so a configured strength survives
   * being switched off and back on.
   */
  bool getEdEnabled() { return m_edEnabled; }
  void setEdEnabled(bool enabled) { m_edEnabled = enabled; }

  /**
   * @brief Get or set dof strength.
   */
  float getDofStrength() { return m_dofStrength; }
  void setDofStrength(float strength) { m_dofStrength = strength; }

  /**
   * @brief Set position of dof
   */
  float getDofPosition() { return m_dofPosition; }
  void setDofPosition(float position) { m_dofPosition = position; }

  /**
   * @brief Get or set the strength of the edge effect.
   *
   * Up to 1.0 this fades the outline in at the one-pixel width the effect has
   * always had. Above 1.0 the outline is fully dark and the value is its
   * half-width in pixels, so 2.5 gives a distinctly bolder outline than 1.0.
   */
  float getEdStrength() { return m_edStrength; }
  void setEdStrength(float strength) { m_edStrength = strength; }

  /**
   * @brief Get or set whether the edge outline is supersampled.
   *
   * On (the default) the edge term is evaluated at four sub-pixel offsets and
   * averaged, so a silhouette that only partly covers a pixel gets an
   * intermediate shade instead of a hard 0 or 1. Off takes a single tap on
   * each pixel centre. It has no effect unless edge detection is enabled.
   */
  bool edgeSupersampling() const;
  void setEdgeSupersampling(bool enabled);

  /**
   * @brief Get or set whether FXAA smooths the finished image (default off).
   *
   * FXAA (fast approximate anti-aliasing) is a luma edge filter run after the
   * ambient occlusion, edge outlines, fog and depth of field have been
   * applied, so it smooths the outlines they draw as well as the silhouettes.
   * It costs an offscreen image the size of the viewport and one more
   * full-screen pass, and only when enabled.
   *
   * It is not an effect of its own: it applies only while the pipeline is
   * already active (see hasActiveEffects()), and enabling it does not make
   * the pipeline active. Without an active effect the solid geometry goes
   * straight to the framebuffer, as always, unsmoothed. It works in device
   * pixels, so it follows setPixelRatio().
   */
  bool antiAliasingEnabled() const;
  void setAntiAliasingEnabled(bool enabled);

private:
  float m_pixelRatio;
  bool m_aoEnabled;
  float m_dofStrength;
  float m_dofPosition;
  bool m_dofEnabled;
  float m_fogPosition;
  Vector4ub m_backgroundColor;
  bool m_fogEnabled;
  float m_aoStrength;
  float m_fogStrength;
  bool m_edEnabled;
  float m_edStrength;
  int m_width;
  int m_height;

  class Private;
  Private* d;
};

} // namespace Avogadro::Rendering
// End namespace Avogadro

#endif
