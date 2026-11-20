#version 400
precision highp float;

in vec3 vertexPosition;
out vec3 vWorldPos;

uniform mat4 uModelView;
uniform mat4 uProjection;
// Maps the unit cube [0,1]^3 (grid index / (n - 1)) to world space; for a
// skewed grid the box is a parallelepiped.
uniform mat4 uBoxMatrix;

void main()
{
    // Transform unit cube [-1,1] to [0,1], then to the world-space box
    vec3 worldPos = (uBoxMatrix * vec4(vertexPosition * 0.5 + 0.5, 1.0)).xyz;
    vWorldPos = worldPos;

    gl_Position = uProjection * uModelView * vec4(worldPos, 1.0);
}
