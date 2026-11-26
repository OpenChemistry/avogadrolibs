/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_CAMERABUFFER_P_H
#define AVOGADRO_RENDERING_CAMERABUFFER_P_H

#include "avogadrorenderingexport.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <cstddef>
#include <string>
#include <type_traits>

namespace Avogadro::Rendering {

class Camera;

/**
 * The uniform buffer binding points the renderer reserves. Every program that
 * declares a block gets it bound to the point named here by the ShaderLibrary
 * (GLSL 420's layout(binding=) is not available in GLSL 400 or ES 3.0).
 */
constexpr unsigned int CameraBufferBindingPoint = 0;
constexpr unsigned int StyleBufferBindingPoint = 1; // Reserved, not used yet.

/**
 * The CPU copy of the CameraBuffer uniform block, laid out as std140. Every
 * member is a mat4 or vec4, so each sits on a 16-byte boundary with no
 * padding, and the matrices are column-major like Eigen's.
 */
struct CameraBlock
{
  float modelView[16];
  float projection[16];
  float inverseProjection[16];
  // The upper-left 3x3 holds the normal matrix (mat3(normalMatrix) in GLSL).
  float normalMatrix[16];
  float viewport[4];     // (width, height, 1/width, 1/height), device pixels
  float cameraParams[4]; // (pixelRatio, nearPlane, farPlane, isOrthographic)
  float sceneBounds[4];  // (center.xyz, radius)
};

static_assert(std::is_standard_layout_v<CameraBlock>,
              "CameraBlock must be standard layout for offsetof");
static_assert(offsetof(CameraBlock, modelView) == 0, "std140 offset");
static_assert(offsetof(CameraBlock, projection) == 64, "std140 offset");
static_assert(offsetof(CameraBlock, inverseProjection) == 128, "std140 offset");
static_assert(offsetof(CameraBlock, normalMatrix) == 192, "std140 offset");
static_assert(offsetof(CameraBlock, viewport) == 256, "std140 offset");
static_assert(offsetof(CameraBlock, cameraParams) == 272, "std140 offset");
static_assert(offsetof(CameraBlock, sceneBounds) == 288, "std140 offset");
static_assert(sizeof(CameraBlock) == 304, "std140 block size");

/**
 * The GLSL declaration of the block, which has to match CameraBlock. The
 * ShaderLibrary inserts it after the #version line of every shader it builds,
 * so the declaration exists once.
 */
AVOGADRORENDERING_EXPORT const char* cameraBlockGlsl();

/**
 * @return @p source with cameraBlockGlsl() inserted on the line after its
 * #version line (at the start if there is none).
 */
AVOGADRORENDERING_EXPORT std::string insertCameraBlock(
  const std::string& source);

/**
 * @class CameraBlockState camerabuffer_p.h
 * @brief The GL-free half of CameraBuffer: builds the CameraBlock for a camera
 * and remembers what it was built from, so that an unchanged camera costs a
 * comparison and nothing else.
 */
class AVOGADRORENDERING_EXPORT CameraBlockState
{
public:
  CameraBlockState();

  /**
   * The values that do not come from a Camera. A pixel ratio that is not a
   * positive finite number is stored as 1, a negative or non-finite scene
   * radius as 0. A change makes the next update() rebuild the block.
   */
  void setFrameParameters(float pixelRatio, const Vector3f& sceneCenter,
                          float sceneRadius);

  /**
   * Rebuild the block if @p camera differs from the one it was last built for
   * (modelView, projection, viewport size) or the frame parameters changed.
   * @return true if block() changed.
   */
  bool update(const Camera& camera);

  /** Forget what the block was built from: the next update() rebuilds. */
  void invalidate() { m_valid = false; }

  const CameraBlock& block() const { return m_block; }

  /** Build the block for a camera. Never produces NaN or infinity. */
  static CameraBlock build(const Camera& camera, float pixelRatio,
                           const Vector3f& sceneCenter, float sceneRadius);

private:
  CameraBlock m_block;
  Matrix4f m_modelView;
  Matrix4f m_projection;
  int m_width = 0;
  int m_height = 0;
  float m_pixelRatio = 1.0f;
  Vector3f m_sceneCenter = Vector3f::Zero();
  float m_sceneRadius = 0.0f;
  bool m_valid = false;
};

/**
 * @class CameraBuffer camerabuffer_p.h
 * @brief A uniform buffer on CameraBufferBindingPoint that holds the camera
 * the drawables project with, shared by every program of a RenderContext.
 *
 * A drawable's render(camera) is not always given the frame camera (the 2D
 * overlay has its own, and tools can render with any), so drawables call
 * use() with theirs: it uploads only if that camera differs from the one the
 * buffer holds. GLRenderer calls it once per frame with the main camera, so
 * in steady state use() is a comparison and one glBindBufferBase.
 *
 * Created on first use() in the current GL context. Private to the rendering
 * library: the header is not installed.
 */
class AVOGADRORENDERING_EXPORT CameraBuffer
{
public:
  CameraBuffer() = default;

  /** Calls release(); do it with the owning context current. */
  ~CameraBuffer();

  CameraBuffer(const CameraBuffer&) = delete;
  CameraBuffer& operator=(const CameraBuffer&) = delete;

  /** The values a use() puts in the block besides the camera's own. */
  void setFrameParameters(float pixelRatio, const Vector3f& sceneCenter,
                          float sceneRadius)
  {
    m_state.setFrameParameters(pixelRatio, sceneCenter, sceneRadius);
  }

  /**
   * Make the buffer hold @p camera and bind it to CameraBufferBindingPoint.
   * @return false if the buffer could not be created.
   */
  bool use(const Camera& camera);

  /** Delete the GL buffer, with its context current. Safe to repeat. */
  void release();

  /**
   * Forget the GL buffer without deleting it, for a buffer whose GL context
   * has been destroyed (its name means nothing elsewhere).
   */
  void abandon();

private:
  CameraBlockState m_state;
  unsigned int m_handle = 0;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_CAMERABUFFER_P_H
