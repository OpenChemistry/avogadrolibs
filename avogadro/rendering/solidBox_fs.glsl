#version 120
varying vec3 vBoxPos;
void main() {
    // Just write out any color, we only care about depth in FBO
    gl_FragColor = vec4(vBoxPos, 0.0);
}