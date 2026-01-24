//////////////////////////////////////////////////////////////////////
//
// No-op shader for rendering a fullscreen quad within the solid pipeline
//
//////////////////////////////////////////////////////////////////////

//
// Input
//

// input coordinates
#version 400
precision highp float;

in vec3 inXYZ;

//
// Output
//

// texture coordinates
out vec2 UV;

void main()
{
  gl_Position = vec4(inXYZ.xyz, 1.0);
  UV = inXYZ.xy * vec2(0.5, 0.5) + vec2(0.5, 0.5);
}
