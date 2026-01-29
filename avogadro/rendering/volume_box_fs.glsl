#version 400
precision highp float;

in vec3 vWorldPos;

out vec4 colorOut;

void main()
{
    // Store world position (will be used for ray marching)
    colorOut = vec4(vWorldPos, 1.0);
}
