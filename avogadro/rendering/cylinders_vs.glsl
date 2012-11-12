attribute vec4 vertex;
attribute vec3 color;
attribute vec3 normal;

varying vec3 fnormal;

void main()
{
  gl_FrontColor = vec4(color, 1.0);
  gl_Position = gl_ModelViewProjectionMatrix * vertex;
  fnormal = normalize(gl_NormalMatrix * normal);
}
