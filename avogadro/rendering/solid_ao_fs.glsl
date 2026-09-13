//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion stage for the solid pipeline
//
// Writes the raw screen-space ambient occlusion term to its own buffer so the
// compositing stage can filter it. The estimator takes 16 samples per pixel
// and rotates the kernel from one pixel to the next; on its own that shows up
// as a dither pattern, so the rotations are laid out on a 4x4 tile that uses
// each of the 16 angles exactly once. Averaging over any 4x4 block of pixels
// then cancels the pattern, which is what the next stage does.
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

//
// Input
//

// texture coordinates
in vec2 UV;

out float outAo;

//
// Uniforms
//

// Depth rendered texture
uniform sampler2D inDepthTex;
// Shadow strength for SSAO
uniform float inAoStrength;
// Rendering surface dimensions, in pixels
uniform float width, height;

vec3 getNormalNear(vec2 normalUV, float cent)
{
  float xpos = texture(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
  float xneg = texture(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
  float ypos = texture(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
  float yneg = texture(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
  float xposdelta = xpos - cent;
  float xnegdelta = cent - xneg;
  float yposdelta = ypos - cent;
  float ynegdelta = cent - yneg;
  float xdelta = abs(xposdelta) > abs(xnegdelta) ? xnegdelta : xposdelta;
  float ydelta = abs(yposdelta) > abs(ynegdelta) ? ynegdelta : yposdelta;
  vec3 r = vec3(xdelta, ydelta, 0.5 / width + 0.5 / height);
  return normalize(r);
}

// Size of the rotation tile, in pixels. Must match AO_BLUR_TILE in
// solid_first_fs.glsl, which averages a block of exactly this size; if the two
// disagree the pattern stops cancelling and the dither returns.
const int AO_TILE = 4;

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

float computeSSAOLuminosity(vec3 normal, float depth)
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
    float occluderDepth = texture(inDepthTex, UV + samplePoint).x;
    vec3 occluder = vec3(samplePoint.xy, depth - occluderDepth);
    float d = length(occluder);
    float occlusion = max(0.0, dot(normal, occluder)) * (1.0 / (1.0 + d));
    totalOcclusion += occlusion;
  }

  return max(0.0, 1.2 - inAoStrength * totalOcclusion);
}

void main() {
  float depth = texture(inDepthTex, UV).x;
  // Can exceed 1.0: the term brightens as well as darkens, so the buffer this
  // is written to has to be a float format rather than a normalized one.
  outAo = computeSSAOLuminosity(getNormalNear(UV, depth), depth);
}
