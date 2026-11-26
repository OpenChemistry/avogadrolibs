/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_SOLIDEFFECTS_P_H
#define AVOGADRO_RENDERING_SOLIDEFFECTS_P_H

#include "avogadrorenderingexport.h"

namespace Avogadro::Rendering {

/**
 * @file solideffects_p.h
 * @brief The settings of the solid pipeline's fog and depth of field, in
 * terms the compositing shader uses, and the same formulas on the CPU.
 *
 * Both effects are measured against the scene's bounding sphere (center depth
 * zc and radius R from the camera block), so they do not depend on how far
 * the camera is or on the projection. Depths are distances in front of the
 * camera in scene units. The functions here make no GL calls; the shader
 * (solid_first_fs.glsl) implements the same arithmetic.
 *
 * Private to the rendering library: the header is not installed. The
 * functions are exported only so that the unit tests can link against them.
 */

/** Largest circle of confusion, in logical pixels, whatever the strength. */
constexpr float MaxDepthOfFieldBlur = 16.0f;

/**
 * The fog, as the shader takes it. The fog is a linear ramp in depth: no fog
 * at zStart = zc + startRadii * R, rising to @c amount at the back of the
 * scene's depth span, zc + R, and staying there. The color is mixed linearly
 * toward the background.
 */
struct FogSettings
{
  /** Fraction of the background mixed in at the back of the span; 0 is off. */
  float amount = 0.0f;
  /** Where the ramp starts, in scene radii from the center (negative: nearer
   * the camera). */
  float startRadii = 0.0f;
};

/**
 * Map the application's fog strength and position to FogSettings.
 *
 * @p strength (the dialog allows -20 to 20, default 1): amount =
 * strength / (strength + 1.5) for a positive strength, so 1 mixes in 40% of
 * the background at the back, 5 mixes in 77% and 20 mixes in 93%. Zero or
 * less (and a non-finite value) turns the fog off.
 *
 * @p position (-20 to 20, default 1; clamped to that range): startRadii =
 * 0.1 * (position - 1). The default starts the fog at the center of the
 * scene. Smaller values start it nearer the camera, down to 2.1 radii in
 * front of the center at -20, which fogs the whole molecule; larger values
 * start it later, up to 0.95 radii behind the center (reached at position
 * 10.5), where the ramp is squeezed into the very back of the scene. The
 * start is capped there, so the ramp is never shorter than 5% of the radius.
 */
AVOGADRORENDERING_EXPORT FogSettings fogSettings(float strength,
                                                 float position);

/** The fog mix fraction (0 to settings.amount) at view depth @p depth. */
AVOGADRORENDERING_EXPORT float fogFactor(const FogSettings& settings,
                                         float depth, float centerDepth,
                                         float radius);

/**
 * The depth of field, as the shader takes it. A point's circle of confusion
 * has a radius, in logical pixels, of
 *   min(blurPerRadius * |depth - focusDepth| / R, maxBlur)
 * where focusDepth = zc + focusRadii * R. The shader multiplies by the pixel
 * ratio to get device pixels.
 */
struct DepthOfFieldSettings
{
  /** Blur radius, in logical pixels, at one scene radius from the focus; 0 is
   * off. */
  float blurPerRadius = 0.0f;
  float maxBlur = MaxDepthOfFieldBlur;
  /** Focus depth, in scene radii from the center (negative: nearer). */
  float focusRadii = 0.0f;
};

/**
 * Map the application's depth of field strength and position to
 * DepthOfFieldSettings.
 *
 * @p strength (0 to 2, default 1): blurPerRadius = 8 * strength logical
 * pixels, so at the default a point a scene radius from the focus blurs over
 * a radius of 8 pixels. Zero or less (and a non-finite value) turns it off;
 * more than 10 is treated as 10.
 *
 * @p position (0 to 20, default 1; clamped to that range): 0 focuses on the
 * front of the scene's bounding sphere (focusRadii -1), 1 on its center, and
 * 20 on its back (focusRadii +1), linearly in between on each side of 1.
 */
AVOGADRORENDERING_EXPORT DepthOfFieldSettings
depthOfFieldSettings(float strength, float position);

/**
 * The circle of confusion radius, in logical pixels, at view depth
 * @p depth. Zero when the scene has no extent (@p radius not positive).
 */
AVOGADRORENDERING_EXPORT float circleOfConfusion(
  const DepthOfFieldSettings& settings, float depth, float centerDepth,
  float radius);

/**
 * The size, in pixels, of the ambient occlusion buffers for a frame @p size
 * pixels across (or high): half of it, rounded up so that an odd frame's last
 * row or column still has a texel, and never less than one. The occlusion is
 * computed and blurred at this size, and each texel stands for a 2x2 block of
 * frame pixels; the last block hangs over the edge when the frame is odd.
 */
AVOGADRORENDERING_EXPORT int occlusionBufferSize(int size);

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_SOLIDEFFECTS_P_H
