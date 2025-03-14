#version 330

in vec3 vBoxPos;
out vec4 outColor;
void main()
{
  vec3 mappedPos = (vBoxPos * 0.5) + 0.5;
  outColor   = vec4(mappedPos, 1.0);
}
