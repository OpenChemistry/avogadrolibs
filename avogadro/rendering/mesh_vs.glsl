attribute vec4 vertex;
attribute vec4 color;
attribute vec3 normal;

uniform mat4 modelView;
uniform mat4 projection;
uniform mat3 normalMatrix;

varying vec3 fnormal;

void main()
{
  gl_FrontColor = vec4(u_color, u_opacity);
  gl_Position = projection * modelView * vertex;
  fnormal = normalize(normalMatrix * normal);
}
