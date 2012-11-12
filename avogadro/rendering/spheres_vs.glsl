attribute vec4 vertex;
attribute vec3 color;
attribute vec2 texCoordinate;
varying vec2 v_texCoord;
varying vec3 fColor;
varying vec4 eyePosition;
varying float radius;

void main()
{
  radius = abs(texCoordinate.x);
  fColor = color;
  v_texCoord = texCoordinate / radius;
  gl_Position = gl_ModelViewMatrix * vertex;
  eyePosition = gl_Position;

  // Test if the closest point on the sphere would be clipped.
  vec4 clipTestNear = eyePosition;
  clipTestNear.z += radius;
  clipTestNear = gl_ProjectionMatrix * clipTestNear;
  if (clipTestNear.z > -clipTestNear.w) {
    // If not, calculate clip coordinate
    gl_Position.xy += texCoordinate;
    gl_Position = gl_ProjectionMatrix * gl_Position;
  }
  else {
    // If so, invalidate the clip coordinate to ensure that it will be clipped.
    gl_Position.w = 0.0;
  }
}
