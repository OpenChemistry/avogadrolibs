/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDPIPELINE_H
#define AVOGADRO_RENDERING_SOLIDPIPELINE_H

#include <avogadro/core/cube.h>
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
  SolidPipeline& operator= (const SolidPipeline&) = delete;

  /**
   * @brief Initialize OpenGL objects.
   */
  void initialize();

  void renderVolumeFaces(const Camera& cam);
  /**
   * @brief Begin solid geometry rendering.
   */
  void begin();


  void beginFront();
  void endFront();
  void beginBack();
  void endBack();
  /**
   * @brief End solid geometry rendering and apply screen-space shaders.
   */
  void end();

  /**
   * @brief Resize buffers for width x height viewport.
   */
  void resize(int width, int height);

  void adjustOffset(const Camera& camera);

  /**
   * @brief Set pixel ratio (1.0 on standard displays, 2.0 on Retina, etc.).
   */
  void setPixelRatio(float ratio);


  /**
   * @brief Get or set whether Ambient Occlusion is enabled.
   */
  bool getAoEnabled() { return m_aoEnabled; }

  void setData(float data);

  float getData() const;


  void setAoEnabled(bool enabled) { m_aoEnabled = enabled; }


  // float backgroundColor() const { return m_backgroundColor; }
  // void setBackgroundColor(const Vector4ub& c) { m_backgroundColor = c; }
  /**
   * @brief Get or set shadow strength for Ambient Occlusion.
   */
  float getAoStrength() { return m_aoStrength; }
  void setAoStrength(float strength) { m_aoStrength = strength; }
  
  // float getBackground() { return background; }

  void setBackgroundX(float strength) { backgroundX = strength; }
  void setBackgroundY(float strength) { backgroundY = strength; }
  void setBackgroundZ(float strength) { backgroundZ = strength; }


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
   * @brief Get or set the strength of the edge effect
   */
  bool getEdStrength() { return m_edStrength; }
  void setEdStrength(float strength) { m_edStrength = strength; }

private:
  float m_pixelRatio;
  bool m_aoEnabled;
  float m_aoStrength;
  bool m_edEnabled;
  float m_edStrength;
  int m_width;
  int m_height;
  float m_currentCube;
  float backgroundX;
  float backgroundY;
  float backgroundZ;
  Eigen::Matrix4f modelyy;

  class Private;
  Private* d;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif
