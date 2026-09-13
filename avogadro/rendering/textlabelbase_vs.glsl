#version 400
precision highp float;
// Modelview/projection matrix
uniform mat4 mv;
uniform mat4 proj;

// anchor position
uniform vec3 anchor;

// Distance to project the label towards the camera
uniform float radius;

// Vertex attributes.
in vec2 offset;
in vec2 texCoord;

// Viewport dimensions:
uniform ivec2 vpDims;

// Texture coordinate.
out vec2 texc;

// Given a clip coordinate, align the vertex to the nearest pixel center.
void alignToPixelCenter(inout vec4 clipCoord)
{
  // Half pixel increments (clip coord span / [2*numPixels] = [2*w] / [2*l]):
  vec2 inc = abs(clipCoord.w) / vec2(vpDims);

  // Fix up coordinates -- pixel centers are at xy = (-w + (2*i + 1) * inc)
  // for the i'th pixel. First find i and floor it. Just solve the above for i:
  ivec2 pixels = ivec2(floor((clipCoord.xy + abs(clipCoord.ww) - inc)
                             / (2. * inc)));

  // Now reapply the equation to obtain a pixel centered offset.
  clipCoord.xy = -abs(clipCoord.ww) + (2. * vec2(pixels) + vec2(1., 1.)) * inc;
}

void main(void)
{
  // Transform to eye coordinates:
  vec4 eyeAnchor = mv * vec4(anchor, 1.0);

  // Apply radius
  // Scale about camera origin, that shifts z forward by radius.
  // eyeAnchor.z is negative for items in front of the camera
  // The scaling factor is:
  // S = eyeAnchor.z'/eyeAnchor.z
  //   = (eyeAnchor.z + radius)/eyeAnchor.z 
  //   = 1 + radius/eyeAnchor.z
  
  float MIN_DEPTH = 1.0e-06;
  if(-eyeAnchor.z > MIN_DEPTH) {
    float scale = 1.0 + radius / eyeAnchor.z; 
    eyeAnchor *= vec4(scale, scale, scale, 1.0);
  }

  // Transform to clip coordinates
  vec4 clipAnchor = proj * eyeAnchor;

  // Move the anchor to a pixel center:
  alignToPixelCenter(clipAnchor);

  // Align offset to cell centers using the w coordinate:
  // Since w determines whether or not the vertex is clipped, (-w, w) spans
  // the width/height of the display. Using the viewport width/height in pixels,
  // we can properly convert the offset into pixel units.
  vec2 conv = (2. * abs(clipAnchor.w)) / vec2(vpDims);

  // Apply the offset:
  gl_Position = clipAnchor + vec4(offset.x * conv.x, offset.y * conv.y, 0., 0.);

  // Pass through the texture coordinate
  texc = texCoord;
}
