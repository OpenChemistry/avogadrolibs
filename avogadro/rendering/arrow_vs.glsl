attribute vec4 vertex;

uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  gl_FrontColor = vec4(0.0, 1.0, 0.0, 1.0);
  gl_Position = projection * modelView * vertex;
}
