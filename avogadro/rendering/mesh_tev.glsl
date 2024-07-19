#version 400
layout (quads) in;

uniform mat4 projection;

const int numControlPoints = 2;
vec3 controlPoints[9];

int index(int i, int j) {
    return i + j * (numControlPoints + 1);
}

float factorial(int n) {
    float result = 1;
    for (int i = 2; i <= n; ++i) {
        result *= i;
    }
    return result;
}

float B(int n, int k, float u) {
    float px = 1;
    if (k > 0) { // pow(x,0) is undefined
        px = pow(u, k);
    }
    float pnk = 1;
    if (n - k > 0) {  // pow(x,0) is undefined
        pnk = pow(1.0 - u, n - k);
    }
    return factorial(n) / (factorial(k) * factorial(n - k)) * px * pnk;
}

vec3 p(float u, float v) {
    vec3 result = vec3(0, 0, 0);
    for (int i = 0; i <= numControlPoints; ++i) {
        for (int j = 0; j <= numControlPoints; ++j) {
            result += B(numControlPoints, i, u) * B(numControlPoints, j, v) * controlPoints[index(i, j)];
        }
    }
    return result;
}

void main(void)
{
    controlPoints[0] = vec3(-1, -1, 0);
    controlPoints[1] = vec3(0, -1, 0);
    controlPoints[2] = vec3(1, -1, 0);
    controlPoints[3] = vec3(-1, 0, 0);
    controlPoints[4] = vec3(0, 0, -5);
    controlPoints[5] = vec3(1, 0, 0);
    controlPoints[6] = vec3(-1, 1, 0);
    controlPoints[7] = vec3(0, 1, 0);
    controlPoints[8] = vec3(1, 1, 0);

    vec3 worldPos = p(gl_TessCoord.x, gl_TessCoord.y);
    gl_Position = projection * vec4(worldPos, 1);
}
