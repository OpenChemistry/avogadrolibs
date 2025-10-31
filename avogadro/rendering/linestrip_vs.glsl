#version 400
precision highp float;

in vec4 vertex;
in vec4 color;

out vec4 outColor;

uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  outColor = color;
  gl_Position = projection * modelView * vertex;
}
