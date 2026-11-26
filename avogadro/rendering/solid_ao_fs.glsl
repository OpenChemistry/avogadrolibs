//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion stage for the solid pipeline
//
// Writes the raw screen-space ambient occlusion term to its own buffer, at half
// the resolution of the frame in each direction, so the blur stages can filter
// it. The estimator takes 16 samples per texel and rotates the kernel from one
// texel to the next; on its own that shows up as a dither pattern, so the
// rotations are laid out on a 4x4 tile that uses each of the 16 angles exactly
// once. Averaging over any 4x4 block of texels then cancels the pattern, which
// is what the blur stages (solid_aoblur_fs.glsl) do.
//
// Each texel stands for a 2x2 block of frame pixels and is evaluated at the
// one of the four nearest the camera. Taking the nearest keeps a texel that
// straddles a silhouette on the molecule rather than on the background behind
// it, so the upsampling in the compositing stage finds foreground texels right
// up to the edge. The kernel is laid out in screen UV units, as before, so the
// occlusion has the same world-space reach at any resolution.
//
// The distance to the surface, in scene units, is written alongside the term.
// The blur and the upsampling need it to tell surfaces apart, and this pass
// has already read the depth it comes from, so carrying it here saves them a
// second depth texture and a per-tap linearization.
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

//
// Output
//

// x: the ambient occlusion term. y: distance from the camera, in scene units.
out vec2 outAo;

//
// Uniforms
//

// Depth rendered texture, at the full resolution of the frame
uniform sampler2D inDepthTex;
// Shadow strength for SSAO
uniform float inAoStrength;
// The projection matrix, used to turn window depth into a distance in scene
// units, comes from the CameraBuffer block that the shader library declares.

// Window depth to distance from the camera, in scene units. Derived from the
// projection so it holds for both the perspective and the orthographic camera,
// rather than assuming fixed near and far planes.
float linearDepth(float depth)
{
  float ndc = depth * 2.0 - 1.0;
  float viewZ = (projection[3][2] - ndc * projection[3][3]) /
                (ndc * projection[2][3] - projection[2][2]);
  return -viewZ;
}

// Screen-space normal from the depth gradient at a pixel: the smaller of the
// forward and backward differences, so a silhouette does not tilt it.
vec3 getNormalNear(ivec2 pixel, ivec2 size, float cent)
{
  ivec2 last = size - ivec2(1);
  float xpos = texelFetch(inDepthTex, min(pixel + ivec2(1, 0), last), 0).x;
  float xneg = texelFetch(inDepthTex, max(pixel - ivec2(1, 0), ivec2(0)), 0).x;
  float ypos = texelFetch(inDepthTex, min(pixel + ivec2(0, 1), last), 0).x;
  float yneg = texelFetch(inDepthTex, max(pixel - ivec2(0, 1), ivec2(0)), 0).x;
  float xposdelta = xpos - cent;
  float xnegdelta = cent - xneg;
  float yposdelta = ypos - cent;
  float ynegdelta = cent - yneg;
  float xdelta = abs(xposdelta) > abs(xnegdelta) ? xnegdelta : xposdelta;
  float ydelta = abs(yposdelta) > abs(ynegdelta) ? ynegdelta : yposdelta;
  vec3 r = vec3(xdelta, ydelta, 0.5 / float(size.x) + 0.5 / float(size.y));
  return normalize(r);
}

// Size of the rotation tile, in texels of this pass. Must match AO_TILE in
// solid_aoblur_fs.glsl, which averages a block of exactly this size; if the two
// disagree the pattern stops cancelling and the dither returns.
const int AO_TILE = 4;

// Distance written for background texels: the largest finite half float. Must
// match the background test (BACKGROUND_THRESHOLD) in solid_aoblur_fs.glsl and
// solid_first_fs.glsl.
const float BACKGROUND_DISTANCE = 65504.0;

// One kernel rotation per pixel of the tile.
const int AO_SAMPLES = AO_TILE * AO_TILE;

const vec2 SSAOkernel[16] = vec2[16](
        vec2(0.072170, 0.081556),
        vec2(-0.035126, 0.056701),
        vec2(-0.034186, -0.083598),
        vec2(-0.056102, -0.009235),
        vec2(0.017487, -0.099822),
        vec2(0.071065, 0.015921),
        vec2(0.040950, 0.079834),
        vec2(-0.087751, 0.065326),
        vec2(0.061108, -0.025829),
        vec2(0.081262, -0.025854),
        vec2(-0.063816, 0.083857),
        vec2(0.043747, -0.068586),
        vec2(-0.089848, 0.049046),
        vec2(-0.065370, 0.058761),
        vec2(0.099581, -0.089322),
        vec2(-0.032077, -0.042826)
    );

float computeSSAOLuminosity(vec3 normal, float depth, vec2 uv)
{
  float totalOcclusion = 0.0;
  // One of AO_SAMPLES kernel rotations, arranged so that each tile-sized block
  // of pixels uses every rotation exactly once. The blur in the next stage
  // averages a block of the same size, so the pattern cancels.
  vec2 tile = mod(gl_FragCoord.xy - 0.5, float(AO_TILE));
  float A = (tile.x + float(AO_TILE) * tile.y) * 2.0 * 3.14159265358979 /
            float(AO_SAMPLES);
  float S = sin(A);
  float C = cos(A);
  mat2 rotation = mat2(
    C, -S,
    S, C
  );
  for (int i = 0; i < AO_SAMPLES; i++) {
    vec2 samplePoint = rotation * SSAOkernel[i];
    float occluderDepth = texture(inDepthTex, uv + samplePoint).x;
    vec3 occluder = vec3(samplePoint.xy, depth - occluderDepth);
    float d = length(occluder);
    float occlusion = max(0.0, dot(normal, occluder)) * (1.0 / (1.0 + d));
    totalOcclusion += occlusion;
  }

  return max(0.0, 1.2 - inAoStrength * totalOcclusion);
}

void main() {
  ivec2 size = textureSize(inDepthTex, 0);
  ivec2 last = size - ivec2(1);
  // The 2x2 block of frame pixels this texel covers. On an odd-sized frame the
  // last texel's block hangs over the edge, and the clamp repeats the edge.
  ivec2 corner = 2 * ivec2(gl_FragCoord.xy);
  ivec2 nearest = min(corner, last);
  float depth = texelFetch(inDepthTex, nearest, 0).x;
  for (int i = 1; i < 4; i++) {
    ivec2 pixel = min(corner + ivec2(i & 1, i >> 1), last);
    float other = texelFetch(inDepthTex, pixel, 0).x;
    if (other < depth) {
      depth = other;
      nearest = pixel;
    }
  }
  if (depth >= 1.0) {
    // Background: skip the 16-tap SSAO kernel and write the FP16-max sentinel
    // distance so the blur and upsampling never mix background into
    // foreground.
    outAo = vec2(1.0, BACKGROUND_DISTANCE);
    return;
  }
  vec2 uv = (vec2(nearest) + 0.5) / vec2(size);
  // The term can exceed 1.0: it brightens as well as darkens, so the buffer
  // this is written to has to be a float format rather than a normalized one.
  outAo = vec2(computeSSAOLuminosity(getNormalNear(nearest, size, depth),
                                     depth, uv),
               linearDepth(depth));
}
