#version 400

// Per-vertex attributes
in vec3 position;     // this endpoint
in vec3 otherEnd;     // the other endpoint of the line segment
in vec4 color;        // RGBA color at this endpoint
in float widthSide;   // half-width * side (-1 or +1)

uniform mat4 modelView;
uniform mat4 projection;

out vec4 outColor;

void main()
{
  // Transform both endpoints to view space
  vec4 viewPos = modelView * vec4(position, 1.0);
  vec3 viewOther = (modelView * vec4(otherEnd, 1.0)).xyz;

  // Line direction in view space
  vec3 lineDir = viewOther - viewPos.xyz;
  float lineLen = length(lineDir);

  // View direction in view space (camera looks along -Z)
  vec3 viewDir = vec3(0.0, 0.0, 1.0);

  vec3 offset;
  if (lineLen > 1e-6) {
    lineDir /= lineLen;
    // Perpendicular to both line direction and view direction
    offset = normalize(cross(lineDir, viewDir)) * widthSide;
  } else {
    // Degenerate line segment - offset in X
    offset = vec3(widthSide, 0.0, 0.0);
  }

  viewPos.xyz += offset;

  gl_Position = projection * viewPos;
  outColor = color;
}
