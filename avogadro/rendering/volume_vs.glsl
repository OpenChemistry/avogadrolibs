#version 400
precision highp float;

in vec3 vertexPosition;

void main()
{
    gl_Position = vec4(vertexPosition, 1.0);
}
