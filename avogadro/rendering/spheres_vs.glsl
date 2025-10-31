#version 400
precision highp float;  
in vec4 vertex;
in vec3 color;
in vec2 texCoordinate;
out vec2 v_texCoord;
out vec3 fColor;
out vec4 eyePosition;
out float radius;

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
