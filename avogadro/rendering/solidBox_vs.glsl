#version 120
attribute vec3 aPosition;
uniform mat4 uMVP;
void main() {
    gl_Position = uMVP * vec4(aPosition, 1.0);
}