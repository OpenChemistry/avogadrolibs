#version 120
attribute vec3 aPosition;
uniform mat4 uMVP;
varying vec3 vBoxPos;
void main() {
    vBoxPos = aPosition;
    gl_Position = uMVP * vec4(aPosition, 1.0);
}

