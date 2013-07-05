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
// the orthographic projection matrix
uniform mat4 u_projection;
// depth texture sampler
uniform sampler2D u_depthTex;
// intensity = 1 / (number of light directions)
uniform float u_intensity;

/**
 * Inverse gnomonic projection over octahedron unfloded into a square. This
 * inverse  projection goes from texture coordinates to the surface of the unit
 * sphere. Both the texture and unit sphere coordinates are in the range
 * [-1, 1].
 *
 * In practice, this function returns the normal vector in model coordinate
 * space. The z is inverted since going from clip coords to NDC inverts the
 * z axis.
 *
 * reference: Tarini et al. page 3, eq. (5)
 */
vec3 textureToSphereSurfaceCoord(in vec2 coord)
{
  vec2 absCoord = abs(coord);
  float h = 1.0 - absCoord.s - absCoord.t;
  return (h >= 0.0) ? vec3(coord.st, -h) : vec3(sign(coord.st) * (1.0 - absCoord.ts), -h);
}

void main()
{
  // map texture coords to normal in model coords
  vec3 N = textureToSphereSurfaceCoord(clamp(v_corner, -1.0, 1.0));

  // model coords -> eye coords
  N = normalize(vec3(u_modelView * vec4(N, 0.0)));

  // add the normal xy components to the sphere eye coords
  vec4 pos = vec4(v_pos, 1.0);
  pos.xy += N.xy * v_radius;
  // eye coord -> clip coords [-1, 1]
  pos = u_projection * pos;
  // clip coords -> [0, 1] for xy and [near, far] for z
  pos.xy = (pos.xy + vec2(1.0, 1.0)) / 2.0;
  pos.z = ((gl_DepthRange.diff * pos.z) + gl_DepthRange.near + gl_DepthRange.far) / 2.0;

  // compute angle between sphere surface and light direction
  float cos_alpha = dot(N, vec3(0, 0, 1));

  // since we are using flat impostors in the depth texture, cos_alpha needs to be positive
  if (cos_alpha > 0.0 && texture2D(u_depthTex, pos.xy).r > pos.z) {
    // the texel is visible from the light source
    gl_FragColor = vec4(vec3(1.0, 1.0, 1.0) * cos_alpha * u_intensity, 1.0);
  } else {
    // texel not visible
    gl_FragColor = vec4(0.0, 0.0, 0.0, 0.0);
  }

}
