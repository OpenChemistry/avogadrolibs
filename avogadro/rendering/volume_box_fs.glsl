#version 120

varying vec3 vBoxPos;

void main()
{
    vec3 mappedPos = (vBoxPos * 0.5) + 0.5;
    gl_FragColor = vec4(mappedPos, 1.0);
}
