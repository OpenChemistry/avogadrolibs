#version 400
precision highp float;

// One instance per cylinder (see CylinderColor): the tube is built here from
// the two ends and the radius. Vertex v of the 16 is ring point j = v >> 1 at
// end v & 1. This repeats CylinderGeometry::tessellate().
in vec3 end1;
in vec3 end2;
in float cylRadius;
// The two colors are 6 bytes at offsets 28..33; read as two ubyte x 4
// attributes so that each is 4-byte aligned:
// colorsA = (r1, g1, b1, r2), colorsB = (g2, b2, unused, unused).
in vec4 colorsA;
in vec4 colorsB;

out vec3 fnormal;
out vec4 outColor;

// cos(j * 2 pi / 8) and sin(j * 2 pi / 8) as tessellate() computes them in
// float.
const float cosines[8] =
  float[8](1.0, 0.707106769, 6.12323426e-17, -0.707106769, -1.0, -0.707106769,
           -1.83697015e-16, 0.707106769);
const float sines[8] =
  float[8](0.0, 0.707106769, 1.0, 0.707106769, 1.22464685e-16, -0.707106769,
           -1.0, -0.707106769);

// Eigen's MatrixBase<Vector3f>::unitOrthogonal() (Geometry/OrthoMethods.h,
// unitOrthogonal_selector<Derived, 3>): isMuchSmallerThan(a, b) is
// abs(a) <= abs(b) * 1e-5 (NumTraits<float>::dummy_precision()).
vec3 unitOrthogonal(vec3 src)
{
  const float prec = 1e-5;
  if (!(abs(src.x) <= abs(src.z) * prec) || !(abs(src.y) <= abs(src.z) * prec)) {
    float invnm = 1.0 / sqrt(src.x * src.x + src.y * src.y);
    return vec3(-src.y * invnm, src.x * invnm, 0.0);
  }
  float invnm = 1.0 / sqrt(src.y * src.y + src.z * src.z);
  return vec3(0.0, -src.z * invnm, src.y * invnm);
}

void main(void)
{
  int ring = gl_VertexID >> 1;
  bool atEnd2 = (gl_VertexID & 1) != 0;

  vec3 axis = end2 - end1;
  float axisLength2 = dot(axis, axis);
  // A zero-length, NaN or non-positive-radius cylinder draws nothing (the CPU
  // path produced NaN vertices): collapse it instead of dividing by zero.
  if (!(axisLength2 > 0.0) || !(cylRadius > 0.0)) {
    outColor = vec4(0.0);
    fnormal = vec3(0.0, 0.0, 1.0);
    gl_Position = vec4(0.0);
    return;
  }

  vec3 direction = axis / sqrt(axisLength2);
  vec3 u = unitOrthogonal(direction) * cylRadius;
  vec3 w = cross(direction, u);
  vec3 radial = cosines[ring] * u + sines[ring] * w;

  vec3 color = atEnd2 ? vec3(colorsA.a, colorsB.x, colorsB.y) : colorsA.rgb;
  vec3 position = (atEnd2 ? end2 : end1) + radial;

  outColor = vec4(color, 1.0);
  gl_Position = projection * modelView * vec4(position, 1.0);
  fnormal = normalize(mat3(normalMatrix) * radial);
}
