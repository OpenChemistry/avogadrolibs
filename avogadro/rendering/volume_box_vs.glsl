#version 330

in vec3 aPosition;
uniform mat4 uMVP;

out vec3 vBoxPos;

void main()
{
  // Pass the box position along:
  vBoxPos = aPosition; // aPosition assumed in [-1..1]
  gl_Position = uMVP * vec4(aPosition, 0.3);
}
