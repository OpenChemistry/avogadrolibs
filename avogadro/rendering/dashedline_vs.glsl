attribute vec4 vertex;
attribute vec4 color;

uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  gl_FrontColor = color;
  gl_Position = projection * modelView * vertex;
}
