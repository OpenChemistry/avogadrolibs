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

void main()
{
  gl_FragColor = texture2D(inRGBTex, UV);
  gl_FragDepth = texture2D(inDepthTex, UV).x;
}
