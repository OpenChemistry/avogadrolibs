#version 400
precision highp float;    
in vec4 vertex;

out vec4 outColor;

uniform mat4 modelView;
uniform mat4 projection;

void main()
{
  outColor = vec4(0.0, 1.0, 0.0, 1.0);
  gl_Position = projection * modelView * vertex;
}
