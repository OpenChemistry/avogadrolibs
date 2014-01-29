//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion shader for sphere impostors
//
// This vertex shader is used for rendering the depth texture from
// the light source's view.
//
//////////////////////////////////////////////////////////////////////

//
// Input
//

// sphere position: model coordinates
attribute vec3 a_pos;
// sphere corner: [-r, -r], [r, -r], [r, r], [-r, r]
attribute vec2 a_corner;

//
// Output
//

// normalized corner: [-1, 1]
varying vec2 v_corner;

//
// Uniforms
//

// model-view matrix of the current light direction
uniform mat4 u_modelView;
// projection matrix
uniform mat4 u_projection;

void main()
{
  // extract radius from unnormalized corner attribute
  float radius = abs(a_corner.s);
  // normalize corner to be in [-1, 1] range
  v_corner = a_corner / radius;

  // model coords -> eye coords
  vec4 pos = u_modelView * vec4(a_pos, 1.0);
  // translate position to corner taking radius into account
  pos.xy += a_corner;
  // eye coords -> clip coords
  gl_Position = u_projection * pos;
}
