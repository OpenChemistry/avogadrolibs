#version 400
precision highp float;

// Per-vertex tubes tessellated on the CPU (CurveGeometry). CylinderGeometry
// builds its tubes in cylinders_vs.glsl instead; both share cylinders_fs.

in vec4 vertex;
in vec3 color;
in vec3 normal;

out vec3 fnormal;
out vec4 outColor;

void main(void)
{
  outColor = vec4(color, 1.0);
  gl_Position = projection * modelView * vertex;
  fnormal = normalize(mat3(normalMatrix) * normal);
}
