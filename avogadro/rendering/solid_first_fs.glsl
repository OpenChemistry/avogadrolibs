//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// At the moment, it does not offer any additional shading functionality.
//
//////////////////////////////////////////////////////////////////////

#version 120

//
// Input
//

// texture coordinates
varying vec2 UV;

//
// Uniforms
//

// RGB rendered texture
uniform sampler2D inRGBTex;
// Depth rendered texture
uniform sampler2D inDepthTex;

const float sampleStep = 0.001;

vec3 getNormalAt(vec2 normalUV)
{
  float xpos = texture2D(inDepthTex, normalUV + vec2(sampleStep, 0.0)).x;
  float xneg = texture2D(inDepthTex, normalUV - vec2(sampleStep, 0.0)).x;
  float ypos = texture2D(inDepthTex, normalUV + vec2(0.0, sampleStep)).x;
  float yneg = texture2D(inDepthTex, normalUV - vec2(0.0, sampleStep)).x;
  float xdelta = xpos - xneg;
  float ydelta = ypos - yneg;
  vec3 r = vec3(xdelta, ydelta, 2.0 * sampleStep);
  return normalize(r);
}

float lerp(float a, float b, float f)
{
    return a + f * (b - a);
}

const vec2 SSAOkernel[16] = vec2[16](
  vec2(-0.00053, 0.00050),
  vec2(-1.41e-05, 0.00078),
  vec2(-0.00041, -0.00078),
  vec2(7.1e-06, 0.00091),
  vec2(0.00067, -3.03e-05),
  vec2(-0.00091, 0.00048),
  vec2(-3.0e-05, 0.00025),
  vec2(-0.00090, -0.00044),
  vec2(-0.00078, 0.00090),
  vec2(-0.00015, 0.00052),
  vec2(-6.6e-05, -0.00090),
  vec2(0.00034, 0.00082),
  vec2(-0.00046, -0.00092),
  vec2(-0.00033, -0.00082),
  vec2(4.6e-05, 2.97e-05),
  vec2(-0.00051, -1.66e-05)
);

const float SSAOstrength = 0.1;

float computeSSAOLuminosity()
{
  vec3 normal = getNormalAt(UV);
  
  float totalOcclusion = 0.0;
  for (int i = 0; i < 16; i++) {
    vec2 samplePoint = SSAOkernel[i];
    float depth = texture2D(inDepthTex, UV + samplePoint).x;
    vec3 occluder = vec3(samplePoint.xy, depth);
    float d = length(occluder);
    float occlusion = max(0.0, dot(normal, occluder)) * (1.0 / (1.0 + d));
    totalOcclusion += occlusion;
  }
  
  return max(0.0, 1.0 - SSAOstrength * totalOcclusion);
}

void main()
{
  float luminosity = 1.0;
  luminosity *= computeSSAOLuminosity();
  vec4 color = texture2D(inRGBTex, UV);
  gl_FragColor = vec4(color.xyz * luminosity, color.w);
  gl_FragDepth = texture2D(inDepthTex, UV).x;
}
