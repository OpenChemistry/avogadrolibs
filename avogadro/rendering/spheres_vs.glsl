attribute vec4 vertex;
attribute vec3 color;
attribute vec2 texCoordinate;
uniform mat4 modelView;
uniform mat4 projection;
varying vec2 v_texCoord;
varying vec3 fColor;
varying vec4 eyePosition;
varying float radius;

void main()
{
  radius = abs(texCoordinate.x);
  fColor = color;
  v_texCoord = texCoordinate / radius;
  gl_Position = modelView * vertex;
  eyePosition = gl_Position;
  gl_Position.xy += texCoordinate;
  gl_Position = projection * gl_Position;
}
