#version 400
precision highp float;

in vec3 vertexPosition;
out vec3 vWorldPos;

uniform mat4 uModelView;
uniform mat4 uProjection;
uniform vec3 uBoxMin;
uniform vec3 uBoxMax;

void main()
{
    // Transform unit cube [-1,1] to world-space cube bounds
    vec3 worldPos = uBoxMin + (vertexPosition * 0.5 + 0.5) * (uBoxMax - uBoxMin);
    vWorldPos = worldPos;

    gl_Position = uProjection * uModelView * vec4(worldPos, 1.0);
}
