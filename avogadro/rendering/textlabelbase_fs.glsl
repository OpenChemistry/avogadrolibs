#version 400
precision highp float;
uniform sampler2D u_texture;
in vec2 texc;

out vec4 outColor;

void main(void)
{
  outColor = texture(u_texture, texc);
  if (outColor.a == 0.)
    discard;
}
