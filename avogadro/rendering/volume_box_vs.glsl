#version 330
layout(location=0) in vec3 vertexPosition;
out vec3 vBoxPos;
uniform mat4 uMVP;
// uniform float scaleFactor; // how much bigger on-screen

void main()
{

  vBoxPos = vertexPosition;
  vec4 clipPos = uMVP * vec4(vertexPosition, 1.0);

  vec3 ndc = clipPos.xyz / clipPos.w;

  ndc.x *= 5.5;
  ndc.y *= 5.5;
  // ndc.z *= 4.0;
  clipPos.xyz = ndc * clipPos.w;

  gl_Position = clipPos;
}
