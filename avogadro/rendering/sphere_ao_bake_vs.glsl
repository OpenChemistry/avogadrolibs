//////////////////////////////////////////////////////////////////////
//
// Ambient occlusion shader for sphere impostors
//
// This fragment shader is used for baking the ambient occlusion
// maps.
//
//////////////////////////////////////////////////////////////////////

//
// Input
//

// sphere center position: model coords
attribute vec3 a_pos;
// corner: [-radius, radius]
attribute vec2 a_corner;
// offset for the center of the sphere's AO map texture tile
attribute vec2 a_tileOffset;

//
// Output
//

// the sphere center position: eye coords
varying vec3 v_pos;
// the sphere radius
varying float v_radius;
// streched corner: [-1.x, 1.x] (see below)
varying vec2 v_corner;

//
// Uniforms
//

// the model-view matrix
uniform mat4 u_modelView;
// the size of the AO texture [pixels] (e.g. 1024)
uniform float u_textureSize;
// the size of a single tile in texture coords [0, 1]
uniform float u_tileSize;

void main()
{
  // pass through radius
  v_radius = abs(a_corner.s);
  // position: model coords -> eye coords
  v_pos = vec3(u_modelView * vec4(a_pos, 1.0));

  // normalize corner: [-radius, radius] -> [-1, 1]
  vec2 corner = a_corner / v_radius;
  // enlarge texture space to trim half a texel from the tile
  // note: v_corner is in range [-1, 1] so we add 2 / (tile size in pixels)
  v_corner = corner * (1.0 + 2.0 / (u_textureSize * u_tileSize));

  // NDC are in range [-1, 1], the  * 2 - 1  translates and scales the position to [0, 1]
  gl_Position = vec4(a_tileOffset * 2.0 - vec2(1.0) + corner * u_tileSize, 0.0, 1.0);
}
