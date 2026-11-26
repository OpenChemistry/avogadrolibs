#version 400
precision highp float;
// One instance per sphere: the quad corner comes from gl_VertexID.
in vec3 center;
in float sphereRadius;
in vec3 color;
out vec2 v_texCoord;
out vec3 fColor;
out vec4 eyePosition;
out float radius;

void main()
{
  // Corners 0..3 are (-1,-1), (-1,1), (1,-1), (1,1).
  vec2 corner = vec2((gl_VertexID & 2) != 0 ? 1.0 : -1.0,
                     (gl_VertexID & 1) != 0 ? 1.0 : -1.0);
  vec2 texCoordinate = corner * sphereRadius;

  radius = abs(texCoordinate.x);
  fColor = color;
  gl_Position = modelView * vec4(center, 1.0);
  eyePosition = gl_Position;

  if (!(radius > 0.0)) {
    // A degenerate sphere draws nothing. Collapse the vertex rather than
    // divide by zero.
    v_texCoord = vec2(0.0);
    gl_Position.w = 0.0;
    return;
  }
  v_texCoord = texCoordinate / radius;

  // Test if the closest point on the sphere would be clipped.
  vec4 clipTestNear = eyePosition;
  clipTestNear.z += radius;
  clipTestNear = projection * clipTestNear;
  if (clipTestNear.z > -clipTestNear.w) {
    // If not, calculate clip coordinate
    gl_Position.xy += texCoordinate;
    gl_Position = projection * gl_Position;
  }
  else {
    // If so, invalidate the clip coordinate to ensure that it will be clipped.
    gl_Position.w = 0.0;
  }
}
