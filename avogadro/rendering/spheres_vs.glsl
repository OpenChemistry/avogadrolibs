attribute vec4 vertex;
attribute vec3 color;
attribute vec2 texCoordinate;
varying vec2 v_texCoord;
varying vec3 fColor;
varying vec4 eyePosition;
varying float radius;

uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  radius = abs(texCoordinate.x);
  fColor = color;
  v_texCoord = texCoordinate / radius;
  gl_Position = modelView * vertex;
  eyePosition = gl_Position;

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
