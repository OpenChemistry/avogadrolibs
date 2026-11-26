//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion blur for the solid pipeline
//
// One direction of a separable blur over the half-resolution occlusion buffer;
// the pipeline runs it horizontally and then vertically. The AO stage rotates
// its sampling kernel across a 4x4 tile of texels, using each rotation exactly
// once, so averaging any 4 consecutive texels along a row and then 4
// consecutive texels down a column averages exactly one block of that size and
// the sampling pattern cancels instead of showing as a dither.
//
// Taps on a different surface are dropped, so occlusion does not bleed across a
// silhouette into whatever lies behind it. The weights are all or nothing,
// rather than falling off smoothly, because that is what keeps the pattern
// cancelling exactly wherever the taps belong to one surface.
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

//
// Output
//

// x: the blurred occlusion term. y: the distance from the camera, unchanged.
out vec2 outAo;

//
// Uniforms
//

// The AO stage's output (or the first pass's): the term in x and the distance
// to the surface in scene units in y.
uniform sampler2D inAoTex;
// 0 blurs along a row, 1 along a column.
uniform int inVertical;
// The projection matrix, used to size the surface test, comes from the
// CameraBuffer block that the shader library declares.

// Must match AO_TILE in solid_ao_fs.glsl.
const int AO_BLUR_TILE = 4;

// Distances at or above this are background; just below BACKGROUND_DISTANCE in
// solid_ao_fs.glsl, the sentinel written there.
const float BACKGROUND_THRESHOLD = 65000.0;

// The steepest surface, in scene units of depth per texel, still treated as one
// surface. Anything steeper is taken to be a different surface.
const float AO_BLUR_SLOPE_LIMIT = 16.0;

// Smallest denominator: keeps a degenerate projection from dividing by zero.
const float DEPTH_EPSILON = 1e-6;

// Scene units that one texel of this buffer covers at a distance from the
// camera. A fixed distance is only right at one zoom level: it would reject
// every tap on a steep surface when zoomed out, which brings the dither back in
// exactly the places the blur exists for. projection[2][3] and [3][3] give the
// perspective divide, which is the view distance for a perspective camera and
// 1 for an orthographic one.
float texelSize(float distance, float texelsHigh)
{
  float wClip = projection[2][3] * -distance + projection[3][3];
  float scale = abs(texelsHigh * projection[1][1]);
  return 2.0 * abs(wClip) / max(scale, DEPTH_EPSILON);
}

void main()
{
  ivec2 size = textureSize(inAoTex, 0);
  ivec2 here = ivec2(gl_FragCoord.xy);
  ivec2 stride = inVertical != 0 ? ivec2(0, 1) : ivec2(1, 0);
  vec2 center = texelFetch(inAoTex, here, 0).xy;
  if (center.y >= BACKGROUND_THRESHOLD) {
    // Nothing to blur, and nothing to blur into.
    outAo = center;
    return;
  }
  float tolerance = AO_BLUR_SLOPE_LIMIT * texelSize(center.y, float(size.y));

  // The centre tap always belongs, so seed with it and skip it in the loop. Any
  // AO_BLUR_TILE consecutive offsets cover the tile, whatever the alignment.
  float total = center.x;
  float weight = 1.0;
  for (int i = -1; i <= AO_BLUR_TILE - 2; i++) {
    if (i == 0)
      continue;
    ivec2 tapPixel = here + i * stride;
    // Off the edge there is nothing to average.
    if (tapPixel.x < 0 || tapPixel.y < 0 || tapPixel.x >= size.x ||
        tapPixel.y >= size.y) {
      continue;
    }
    vec2 tap = texelFetch(inAoTex, tapPixel, 0).xy;
    // Reject background texels as well as taps on a different foreground
    // surface.
    if (tap.y < BACKGROUND_THRESHOLD && abs(tap.y - center.y) < tolerance) {
      total += tap.x;
      weight += 1.0;
    }
  }
  outAo = vec2(total / weight, center.y);
}
