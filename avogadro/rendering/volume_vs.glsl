#version 400
precision highp float;

out vec2 vNdc;

void main()
{
  // Procedural fullscreen triangle covering [-1, 1]^2:
  // Vertices 0, 1, 2 -> (-1, -1), (3, -1), (-1, 3).
  vec2 pos = vec2((gl_VertexID & 1) << 2, (gl_VertexID & 2) << 1) - 1.0;
  gl_Position = vec4(pos, 0.0, 1.0);
  vNdc = pos;
}
