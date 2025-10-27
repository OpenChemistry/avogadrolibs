/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDPIPELINE_H
#define AVOGADRO_RENDERING_SOLIDPIPELINE_H

#include "camera.h"

namespace Avogadro {
namespace Rendering {

class SolidPipeline
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
   * @brief Begin solid geometry rendering.
   */
  void begin();

  void adjustOffset(const Camera& camera);
  /**
   * @brief End solid geometry rendering and apply screen-space shaders.
   */
  void end();

  /**
   * @brief Resize buffers for width x height viewport.
   */
  void resize(int width, int height);

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
   */
  bool getEdEnabled() { return m_edEnabled; }
  void setEdEnabled(bool enabled)
  {
    m_edEnabled = enabled;
    m_edStrength = (m_edEnabled) ? 1.0 : 0.0;
  }

  /**
   * @brief Get or set dof strength.
   */
  float getDofStrength() { return m_dofStrength; }
  void setDofStrength(float strength) { m_dofStrength = strength; }

  /**
   * @brief Set positon of dof
   */
  float getDofPosition() { return m_dofPosition; }
  void setDofPosition(float position) { m_dofPosition = position; }

  /**
   * @brief Get or set the strength of the edge effect
   */
  bool getEdStrength() { return m_edStrength; }
  void setEdStrength(float strength) { m_edStrength = strength; }

private:
  float m_pixelRatio;
  bool m_aoEnabled;
  float m_dofStrength;
  float m_dofPosition;
  bool m_dofEnabled;
  float m_fogPosition;
  Vector4ub m_backgroundColor;
  Eigen::Affine3f modelView;
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

} // End namespace Rendering
} // End namespace Avogadro

#endif