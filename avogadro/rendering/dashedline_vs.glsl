uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  gl_FrontColor = gl_Color;
  gl_Position = projection * modelView * gl_Vertex;
}
