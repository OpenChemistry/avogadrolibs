//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// It offers ambient occlusion and edge detection capabilities.
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

//
// Input
//

// texture coordinates
in vec2 UV;

out vec4 outColor;

//
// Uniforms
//

// RGB rendered texture
uniform sampler2D inRGBTex;
// Depth rendered texture
uniform sampler2D inDepthTex;
// 1.0 if enabled, 0.0 if disabled
uniform float inAoEnabled;
// Shadow strength for SSAO
uniform float inAoStrength;
// 1.0 if enabled, 0.0 if disabled
uniform float inEdStrength;
// Rendering surface dimensions, in pixels
uniform float width, height;

vec3 getNormalAt(vec2 normalUV)
{
  float xpos = texture2D(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
  float xneg = texture2D(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
  float ypos = texture2D(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
  float yneg = texture2D(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
  float xdelta = xpos - xneg;
  float ydelta = ypos - yneg;
  vec3 r = vec3(xdelta, ydelta, 1.0 / width + 1.0 / height);
  return normalize(r);
}

vec3 getNormalNear(vec2 normalUV)
{
  float cent = texture2D(inDepthTex, normalUV).x;
  float xpos = texture2D(inDepthTex, normalUV + vec2(1.0 / width, 0.0)).x;
  float xneg = texture2D(inDepthTex, normalUV - vec2(1.0 / width, 0.0)).x;
  float ypos = texture2D(inDepthTex, normalUV + vec2(0.0, 1.0 / height)).x;
  float yneg = texture2D(inDepthTex, normalUV - vec2(0.0, 1.0 / height)).x;
  float xposdelta = xpos - cent;
  float xnegdelta = cent - xneg;
  float yposdelta = ypos - cent;
  float ynegdelta = cent - yneg;
  float xdelta = abs(xposdelta) > abs(xnegdelta) ? xnegdelta : xposdelta;
  float ydelta = abs(yposdelta) > abs(ynegdelta) ? ynegdelta : yposdelta;
  vec3 r = vec3(xdelta, ydelta, 0.5 / width + 0.5 / height);
  return normalize(r);
}

float lerp(float a, float b, float f)
{
    return a + f * (b - a);
}

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

float computeSSAOLuminosity(vec3 normal)
{
  float totalOcclusion = 0.0;
  float depth = texture2D(inDepthTex, UV).x;
  float A = (width * UV.x + 10 * height * UV.y) * 2.0 * 3.14159265358979 * 5.0 / 16.0;
  float S = sin(A);
  float C = cos(A);
  mat2 rotation = mat2(
    C, -S,
    S, C
  );
  for (int i = 0; i < 16; i++) {
    vec2 samplePoint = rotation * SSAOkernel[i];
    float occluderDepth = texture2D(inDepthTex, UV + samplePoint).x;
    vec3 occluder = vec3(samplePoint.xy, depth - occluderDepth);
    float d = length(occluder);
    float occlusion = max(0.0, dot(normal, occluder)) * (1.0 / (1.0 + d));
    totalOcclusion += occlusion;
  }
  
  return max(0.0, 1.2 - inAoStrength * totalOcclusion);
}

float computeEdgeLuminosity(vec3 normal)
{
  return max(0.0, pow(normal.z - 0.1, 1.0 / 3.0));
}

void main()
{
  float luminosity = 1.0;
  luminosity *= max(1.2 * (1.0 - inAoEnabled), computeSSAOLuminosity(getNormalNear(UV)));
  luminosity *= max(1.0 - inEdStrength, computeEdgeLuminosity(getNormalAt(UV)));

  vec4 color = texture2D(inRGBTex, UV);
  outColor = vec4(color.xyz * luminosity, color.w);
  gl_FragDepth = texture2D(inDepthTex, UV).x;
}
