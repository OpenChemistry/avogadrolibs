//////////////////////////////////////////////////////////////////////
//
// Procedural fullscreen triangle for the solid pipeline
//
//////////////////////////////////////////////////////////////////////

#version 400
precision highp float;

// texture coordinates
out vec2 UV;

void main()
{
  // Vertices 0, 1, 2 cover [-1, 1]^2: (-1, -1), (3, -1), (-1, 3).
  vec2 pos = vec2((gl_VertexID & 1) << 2, (gl_VertexID & 2) << 1) - 1.0;
  gl_Position = vec4(pos, 0.0, 1.0);
  UV = pos * 0.5 + 0.5;
}
