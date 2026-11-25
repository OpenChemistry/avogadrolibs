#version 400
precision highp float;

in vec4 vertex;
in vec4 color;
in vec3 normal;

out vec3 fnormal;
out vec4 outColor;

void main()
{
  outColor = color;
  gl_Position = projection * modelView * vertex;
  fnormal = normalize(mat3(normalMatrix) * normal);
}
