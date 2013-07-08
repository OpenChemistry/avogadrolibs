//
// Input
//

// sphere position: model coordinates
attribute vec3 a_pos;
// sphere corner: [-r, -r], [r, -r], [r, r], [-r, r]
attribute vec2 a_corner;
// offset for the center of the sphere's AO map texture tile
attribute vec2 a_tileOffset;
// color: RGB
attribute vec3 a_color;

//
// Output
//

// normalized corner
varying vec2 v_corner;
// color
varying vec3 v_color;
// position in eye-coordinate space
varying vec4 v_eyePos;
// sphere radius
varying float v_radius;
// AO tile offset
varying vec2 v_tileOffset;

//
// Uniforms
//

// model-view matrix
uniform mat4 u_modelView;
// projection matrix
uniform mat4 u_projection;

#define CONTOUR_LINES
#ifdef CONTOUR_LINES
const float contourWidth = 0.3;
#endif


void main()
{
  // pass through AO tile offset & color
  v_tileOffset = a_tileOffset;
  v_color = a_color;
  // extract radius from unnormalized corner attribute
  v_radius = abs(a_corner.x);
  // normalize corner to be in [-1, 1] range
#ifdef CONTOUR_LINES
  v_corner = a_corner / v_radius + sign(a_corner) * vec2(contourWidth, contourWidth);
#else
  v_corner = a_corner / v_radius;
#endif
  // compute eye-coordinate sphere position
  v_eyePos = u_modelView * vec4(a_pos, 1.0);

  // test if the closest point on the sphere would be clipped
  vec4 clipTestNear = v_eyePos;
  // z-axis points to eye (camera), add radius to sphere position
  clipTestNear.z += v_radius;
  // project the eye-coordinate sphere position
  clipTestNear = u_projection * clipTestNear;
  if (clipTestNear.z > -clipTestNear.w) {
    // not clipped, calculate clip coordinate
    gl_Position = v_eyePos;
#ifdef CONTOUR_LINES
    gl_Position.xy += a_corner + sign(a_corner) * vec2(contourWidth, contourWidth);
    //gl_Position.xy += a_corner;
#else
    gl_Position.xy += a_corner;
#endif
    gl_Position = u_projection * gl_Position;
  } else {
    // clipped, invalidate the clip coordinate to ensure that it will be clipped
    gl_Position.w = 0.0;
  }
}
