//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion shader for sphere impostors
//
// This fragment shader is used for rendering the depth texture from
// the light source's view.
//
//////////////////////////////////////////////////////////////////////

//
// Input
//

// normalized corner: [-1, 1]
#version 400
precision highp float;

in vec2 v_corner;

out vec4 outColor;

void main()
{
  // figure out if we are inside our sphere
  float zz = 1.0 - v_corner.x * v_corner.x - v_corner.y * v_corner.y;
  if (zz <= 0.0)
    discard;

  // draw buffer is not attached, output any color
  outColor = vec4(1.0, 1.0, 1.0, 1.0);
}
