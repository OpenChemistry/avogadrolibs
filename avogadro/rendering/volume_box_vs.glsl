#version 120

attribute vec3 vertexPosition;
varying vec3 vBoxPos;
uniform mat4 uMVP;

void main()
{
    vBoxPos = vertexPosition;
    vec4 clipPos = uMVP * vec4(vertexPosition, 1.0);
    vec3 ndc = clipPos.xyz / clipPos.w;
    ndc.x *= 5.5;
    ndc.y *= 5.5;
    clipPos.xyz = ndc * clipPos.w;
    gl_Position = clipPos;
}
