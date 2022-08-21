//////////////////////////////////////////////////////////////////////
//
// First-stage screen-space fragment shader for the solid pipeline
//
// At the moment, it does not offer any additional shading functionality.
//
//////////////////////////////////////////////////////////////////////

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

float computeLightingLuminosity()
{
  vec3 normal = getNormalAt(UV);
  float r = 1.0 - normal.y;
  return r;
}

void main()
{
  float luminosity = 1.0;
  luminosity *= computeLightingLuminosity();
  vec4 color = texture2D(inRGBTex, UV);
  gl_FragColor = vec4(color.xyz * luminosity, color.w);
  gl_FragDepth = texture2D(inDepthTex, UV).x;
}
